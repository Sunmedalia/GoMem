package memory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/logging"
)

type S3Options struct {
	Region    string
	Endpoint  string
	PathStyle bool
	Anonymous bool
	Client    *s3.Client // Optional caller-configured SDK client; credentials stay in the SDK.
}
type CloudObjectInfo struct {
	Metageneration string `json:"metageneration,omitempty"`
	Region         string `json:"region,omitempty"`
	Endpoint       string `json:"endpoint,omitempty"`
	Schema         string `json:"schema"`
	Protocol       string `json:"protocol"`
	Bucket         string `json:"bucket"`
	Key            string `json:"key"`
	Version        string `json:"version,omitempty"`
	ETag           string `json:"etag"`
	Size           uint64 `json:"size"`
}
type cloudLocation struct{ bucket, key, version, name string }

func parseS3Location(location string) (cloudLocation, error) {
	var parsed cloudLocation
	if len(location) > 65536 {
		return parsed, fmt.Errorf("S3 URL exceeds length budget")
	}
	u, err := url.Parse(location)
	if err != nil || !strings.EqualFold(u.Scheme, "s3") || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Host == "" || u.Port() != "" || strings.ContainsAny(u.Host, ":[]%") {
		return parsed, fmt.Errorf("invalid S3 image URL")
	}
	if len(u.Host) > 63 || len(u.Host) < 3 || strings.IndexFunc(u.Host, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') }) >= 0 {
		return parsed, fmt.Errorf("invalid S3 bucket name")
	}
	key := strings.TrimPrefix(u.Path, "/")
	if key == "" || len(key) > 1024 || strings.ContainsAny(key, "\r\n\x00") {
		return parsed, fmt.Errorf("invalid S3 object key")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) > 1 || len(query) > 0 && len(query["versionId"]) != 1 {
		return parsed, fmt.Errorf("S3 URL accepts only one versionId")
	}
	version := query.Get("versionId")
	if len(query) > 0 && version == "" || len(version) > 1024 || strings.ContainsAny(version, "\r\n\x00") {
		return parsed, fmt.Errorf("invalid S3 version ID")
	}
	u.Scheme = "s3"
	u.RawQuery = ""
	u.ForceQuery = false
	return cloudLocation{bucket: u.Host, key: key, version: version, name: u.String()}, nil
}
func strongObjectTag(tag string) bool {
	return len(tag) > 2 && len(tag) <= 8192 && tag[0] == '"' && tag[len(tag)-1] == '"' && strings.IndexFunc(tag[1:len(tag)-1], func(r rune) bool { return r < 0x21 || r == 0x7f || r == '"' }) < 0
}
func cloudFailure(ctx context.Context, protocol, operation string, cause error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(cause, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var network net.Error
	if errors.As(cause, &network) && network.Timeout() {
		return context.DeadlineExceeded
	}
	// SDK errors include URLs, request IDs and server response bodies. Keep them out of cases.
	return fmt.Errorf("%s %s failed", protocol, operation)
}
func newS3Client(ctx context.Context, options S3Options) (*s3.Client, error) {
	if options.Client != nil {
		return options.Client, nil
	}
	if options.Endpoint != "" {
		u, err := url.Parse(options.Endpoint)
		if err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("invalid S3 endpoint")
		}
		if u.Scheme == "http" {
			ip := net.ParseIP(u.Hostname())
			if ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("S3 plaintext endpoint is limited to loopback")
			}
		}
	}
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("S3 redirects are not followed") }}
	load := []func(*awsconfig.LoadOptions) error{awsconfig.WithHTTPClient(client), awsconfig.WithLogger(logging.Nop{}), awsconfig.WithClientLogMode(0)}
	if options.Region != "" {
		load = append(load, awsconfig.WithRegion(options.Region))
	}
	if options.Anonymous {
		load = append(load, awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, load...)
	if err != nil {
		return nil, cloudFailure(ctx, "S3", "configuration", err)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("S3 requires --s3-region or an AWS configured region")
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = options.PathStyle
		if options.Endpoint != "" {
			o.BaseEndpoint = aws.String(options.Endpoint)
		}
	}), nil
}

type S3Source struct {
	client   *s3.Client
	location cloudLocation
	info     CloudObjectInfo
	version  *string
	closed   atomic.Bool
	life     context.Context
	cancel   context.CancelFunc
}

func OpenS3(ctx context.Context, location string, options S3Options) (*S3Source, error) {
	parsed, err := parseS3Location(location)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	operation, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client, err := newS3Client(operation, options)
	if err != nil {
		return nil, err
	}
	var version *string
	if parsed.version != "" {
		version = aws.String(parsed.version)
	}
	head, err := client.HeadObject(operation, &s3.HeadObjectInput{Bucket: aws.String(parsed.bucket), Key: aws.String(parsed.key), VersionId: version})
	if err != nil {
		return nil, cloudFailure(operation, "S3", "object metadata", err)
	}
	if head.ContentLength == nil || *head.ContentLength <= 0 || !strongObjectTag(aws.ToString(head.ETag)) || head.DeleteMarker != nil && *head.DeleteMarker {
		return nil, fmt.Errorf("S3 requires a nonempty object with an ETag")
	}
	resolved := aws.ToString(head.VersionId)
	if parsed.version != "" && resolved != parsed.version {
		return nil, fmt.Errorf("S3 requested version does not match response")
	}
	if len(resolved) > 1024 || strings.ContainsAny(resolved, "\r\n\x00") {
		return nil, fmt.Errorf("invalid S3 response version")
	}
	// A null version can be replaced in an unversioned/suspended bucket; If-Match remains mandatory.
	if resolved != "" && resolved != "null" {
		version = aws.String(resolved)
	}
	clientOptions := client.Options()
	endpoint := "aws:s3"
	if clientOptions.BaseEndpoint != nil {
		u, err := url.Parse(*clientOptions.BaseEndpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid resolved S3 endpoint")
		}
		u.User = nil
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		endpoint = u.String()
	}
	life, stop := context.WithCancel(context.Background())
	return &S3Source{client: client, location: parsed, version: version, life: life, cancel: stop, info: CloudObjectInfo{Schema: "gomem.cloud-object/v1", Protocol: "s3", Region: clientOptions.Region, Endpoint: endpoint, Bucket: parsed.bucket, Key: parsed.key, Version: resolved, ETag: *head.ETag, Size: uint64(*head.ContentLength)}}, nil
}
func (s *S3Source) Name() string                     { return s.location.name }
func (s *S3Source) Size() uint64                     { return s.info.Size }
func (s *S3Source) CloudObjectInfo() CloudObjectInfo { return s.info }
func (s *S3Source) Close() error                     { s.closed.Store(true); s.cancel(); return nil }
func (s *S3Source) operation(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if s.closed.Load() {
		return nil, nil, fmt.Errorf("S3 source closed")
	}
	request, cancel := context.WithTimeout(ctx, 60*time.Second)
	stop := context.AfterFunc(s.life, cancel)
	return request, func() { stop(); cancel() }, nil
}
func (s *S3Source) Validate(ctx context.Context) error {
	request, done, err := s.operation(ctx)
	if err != nil {
		return err
	}
	defer done()
	head, err := s.client.HeadObject(request, &s3.HeadObjectInput{Bucket: aws.String(s.info.Bucket), Key: aws.String(s.info.Key), VersionId: s.version, IfMatch: aws.String(s.info.ETag)})
	if err != nil {
		return cloudFailure(request, "S3", "identity check", err)
	}
	if head.ContentLength == nil || *head.ContentLength < 0 || uint64(*head.ContentLength) != s.Size() || aws.ToString(head.ETag) != s.info.ETag || aws.ToString(head.VersionId) != s.info.Version || aws.ToBool(head.DeleteMarker) {
		return fmt.Errorf("S3 object identity changed")
	}
	return nil
}
func (s *S3Source) ReadAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	request, done, err := s.operation(ctx)
	if err != nil {
		return 0, err
	}
	defer done()
	if len(p) > MaxRead {
		return 0, fmt.Errorf("S3 read exceeds budget")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if offset >= s.Size() {
		return 0, io.EOF
	}
	length := min(uint64(len(p)), s.Size()-offset)
	last := offset + length - 1
	output, err := s.client.GetObject(request, &s3.GetObjectInput{Bucket: aws.String(s.info.Bucket), Key: aws.String(s.info.Key), VersionId: s.version, IfMatch: aws.String(s.info.ETag), Range: aws.String("bytes=" + strconv.FormatUint(offset, 10) + "-" + strconv.FormatUint(last, 10))})
	if err != nil {
		return 0, cloudFailure(request, "S3", "range read", err)
	}
	if output.Body == nil {
		return 0, fmt.Errorf("S3 response has no body")
	}
	defer output.Body.Close()
	first, end, total, err := parseContentRange(aws.ToString(output.ContentRange))
	if err != nil || first != offset || end != last || total != s.Size() || output.ContentLength == nil || *output.ContentLength < 0 || uint64(*output.ContentLength) != length {
		return 0, fmt.Errorf("S3 inconsistent range response")
	}
	if aws.ToString(output.ETag) != s.info.ETag || aws.ToString(output.VersionId) != s.info.Version || aws.ToBool(output.DeleteMarker) {
		return 0, fmt.Errorf("S3 object identity changed")
	}
	n, err := io.ReadFull(output.Body, p[:int(length)])
	if err != nil {
		return n, cloudFailure(request, "S3", "body read", err)
	}
	var extra [1]byte
	count, err := output.Body.Read(extra[:])
	if count != 0 || err != io.EOF {
		return n, cloudFailure(request, "S3", "body completion", err)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
