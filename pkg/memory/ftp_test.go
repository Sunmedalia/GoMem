package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
)

func TestFTPBinarySnapshotAndConcurrentReads(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 2, 255, '\r', '\n'}, 16384)
	for _, pasv := range []bool{false, true} {
		server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{Files: map[string][]byte{"dir/memory.raw": data}, PASVOnly: pasv})
		dir := t.TempDir()
		location := strings.Replace(server.URL(), "ftp://", "ftp://secret-user:secret-password@", 1) + "/dir/memory.raw;type=i"
		source, err := OpenFTP(context.Background(), location, FTPOptions{Directory: dir})
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		sum := sha256.Sum256(data)
		capture := source.SnapshotInfo()
		if capture.Size != uint64(len(data)) || capture.SHA256 != hex.EncodeToString(sum[:]) || capture.RemoteSize == nil || *capture.RemoteSize != uint64(len(data)) || capture.RemoteModified != "2020-01-02T03:04:05Z" {
			t.Fatal(capture)
		}
		if strings.Contains(source.Name(), "secret-") {
			t.Fatal("credentials leaked")
		}
		if capture.RemoteSize != nil {
			*capture.RemoteSize = 0
		}
		if *source.SnapshotInfo().RemoteSize != uint64(len(data)) {
			t.Fatal("capture metadata mutable")
		}
		server.SetFile("dir/memory.raw", []byte("remote replaced after acquisition"))
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Go(func() {
				buffer := make([]byte, 4096)
				n, err := source.ReadAt(context.Background(), buffer, 1000)
				if err != nil || n != len(buffer) || !bytes.Equal(buffer, data[1000:5096]) {
					t.Errorf("snapshot read %d %v", n, err)
				}
			})
		}
		wg.Wait()
		if err := source.Validate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if server.Retrievals.Load() != 1 {
			t.Fatal("analysis reconnected")
		}
		commands := strings.Join(server.Commands(), "\n")
		if !strings.Contains(commands, "TYPE I") || !strings.Contains(commands, "RETR memory.raw") {
			t.Fatal(commands)
		}
		for _, forbidden := range []string{"STOR ", "DELE ", "APPE ", "REST "} {
			if strings.Contains(commands, forbidden) {
				t.Fatal("unexpected source mutation or random network read")
			}
		}
		if _, err := source.ReadAt(context.Background(), make([]byte, MaxRead+1), 0); err == nil {
			t.Fatal("unbounded read")
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatal("snapshot leaked", entries, err)
		}
		if _, err := source.ReadAt(context.Background(), make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
	}
}
func TestFTPAcquisitionFailuresRemoveSnapshots(t *testing.T) {
	truncated := 3
	for _, test := range []struct {
		name    string
		options testfixture.FTPServerOptions
		max     uint64
	}{
		{"truncated", testfixture.FTPServerOptions{TruncateBytes: &truncated}, 0},
		{"bad-completion", testfixture.FTPServerOptions{BadCompletion: true}, 0},
		{"changed-size", testfixture.FTPServerOptions{ChangeSize: true}, 0},
		{"changed-time", testfixture.FTPServerOptions{ChangeTime: true}, 0},
		{"understated-size", testfixture.FTPServerOptions{ReportedSizeDelta: -1}, 0},
		{"overstated-size", testfixture.FTPServerOptions{ReportedSizeDelta: 1}, 0},
		{"login-echo", testfixture.FTPServerOptions{RejectLogin: true}, 0},
		{"known-byte-limit", testfixture.FTPServerOptions{}, 2},
		{"unknown-byte-limit", testfixture.FTPServerOptions{NoSize: true}, 2},
		{"empty", testfixture.FTPServerOptions{}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte("byte-exact capture")
			if test.name == "empty" {
				data = nil
			}
			test.options.Files = map[string][]byte{"memory.raw": data}
			server := testfixture.StartFTPServer(t, test.options)
			dir := t.TempDir()
			source, err := OpenFTP(context.Background(), strings.Replace(server.URL(), "ftp://", "ftp://secret-user:secret-password@", 1)+"/memory.raw", FTPOptions{Directory: dir, MaxBytes: test.max})
			if err == nil {
				source.Close()
				t.Fatal("invalid acquisition accepted")
			}
			if strings.Contains(err.Error(), "secret-") {
				t.Fatal("secret leaked")
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil || len(entries) != 0 {
				t.Fatal("partial snapshot retained", entries, readErr)
			}
		})
	}
}
func TestFTPOptionalMetadataAndLocalMutation(t *testing.T) {
	server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{Files: map[string][]byte{"memory.raw": []byte("snapshot bytes")}, NoSize: true, NoTime: true})
	source, err := OpenFTP(context.Background(), server.URL()+"/memory.raw", FTPOptions{Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if source.SnapshotInfo().RemoteSize != nil || source.SnapshotInfo().RemoteModified != "" {
		t.Fatal("invented remote metadata")
	}
	if err := os.WriteFile(source.path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.Validate(context.Background()); err == nil {
		t.Fatal("local mutation undetected")
	}
}
func TestFTPCancellationAndIdleTimeout(t *testing.T) {
	for _, stage := range []string{"greeting", "login", "data", "final"} {
		t.Run(stage, func(t *testing.T) {
			stalled := make(chan struct{}, 1)
			server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{Files: map[string][]byte{"memory.raw": []byte("fixed bytes")}, Stall: stage, Stalled: stalled})
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				source, err := OpenFTP(ctx, server.URL()+"/memory.raw", FTPOptions{Directory: dir})
				if source != nil {
					source.Close()
				}
				result <- err
			}()
			select {
			case <-stalled:
			case <-time.After(3 * time.Second):
				t.Fatal("fixture did not stall")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancellation blocked")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("cancelled snapshot leaked", err)
			}
		})
	}
	server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{Stall: "greeting"})
	started := time.Now()
	_, err := OpenFTP(context.Background(), server.URL()+"/memory.raw", FTPOptions{IdleTimeout: 30 * time.Millisecond})
	if !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("idle timeout missing", err)
	}
}
func TestFTPURIAndOfflineControls(t *testing.T) {
	cases := []struct{ url, dir, file string }{
		{"ftp://user:password@host/dir/file%20name.raw", "dir", "file name.raw"},
		{"ftp://host/%2Fabsolute/file.raw;type=i", "/absolute", "file.raw"},
		{"ftp://host/%2Froot.raw", "/", "root.raw"},
		{"ftp://host/memory.raw", "", "memory.raw"},
	}
	for _, test := range cases {
		location, err := parseFTPLocation(test.url)
		if err != nil || location.directory != test.dir || location.file != test.file || strings.Contains(location.display, "password") {
			t.Fatal(location, err)
		}
	}
	for _, location := range []string{"ftp://host/", "ftp://host/a;type=a", "ftp://host/a?password=secret", "ftp://host/a#x", "ftp://host:0/a", "ftp://host:65536/a", "ftp://user%0a:pass@host/a", "ftp://host/a%0d%0aSTOR%20x", "ftp://host/%00", "ftp://host/.."} {
		if _, err := parseFTPLocation(location); err == nil {
			t.Fatal("invalid FTP URL accepted")
		}
	}
	server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{})
	source, err := OpenSource(context.Background(), server.URL()+"/memory.raw", true)
	if err == nil || source != nil {
		t.Fatal("offline network source", source, err)
	}
	if len(server.Commands()) != 0 {
		t.Fatal("offline sent commands")
	}
	if sourceExtension("ftp://host/capture.vmem%3Btype=i") == ".vmem" || sourceExtension("ftp://host/capture.vmem;type=i") != ".vmem" || replaceSourceExtension("ftp://host/capture.vmem;type=i", ".vmss") != "ftp://host/capture.vmss;type=i" {
		t.Fatal("binary suffix broke pair discovery")
	}
}

func TestFTPActualPinnedResourceAccessor(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for actual locked ResourceAccessor control")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("native-FTP\x00\r\n\xff"), 8192)
	for _, control := range []struct {
		path, key string
		pasv      bool
	}{
		{"/folder/memory.raw", "folder/memory.raw", false},
		{"/folder/memory.raw;type=i", "folder/memory.raw", true},
		{"/%2Fabsolute/memory.raw", "/absolute/memory.raw", false},
		{"/%2Froot.raw", "/root.raw", true},
	} {
		server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{Files: map[string][]byte{control.key: data}, PASVOnly: control.pasv})
		location := server.URL() + control.path
		command := exec.Command(python, "../../tools/ftp_reference.py", "--source", baseline, "--url", location)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixed reference failed for %s: %v %s commands=%v", control.path, err, output, server.Commands())
		}
		var reference struct {
			Baseline string `json:"baseline_commit"`
			Size     uint64
			SHA256   string
			Reads    []struct {
				Offset uint64
				Data   []byte
			}
		}
		if err := json.Unmarshal(output, &reference); err != nil {
			t.Fatal(err)
		}
		source, err := OpenFTP(context.Background(), location, FTPOptions{Directory: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if reference.Baseline != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || source.Size() != reference.Size || source.SnapshotInfo().SHA256 != reference.SHA256 {
			t.Fatal("fixed source bytes differ")
		}
		for _, read := range reference.Reads {
			actual := make([]byte, len(read.Data))
			n, err := source.ReadAt(context.Background(), actual, read.Offset)
			if err != nil || n != len(actual) || !bytes.Equal(actual, read.Data) {
				t.Fatal("fixed seek/read mismatch", err)
			}
		}
	}
}

func TestFTPControlReplyBudget(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan struct{})
	go func() { defer close(done); right.Write(bytes.Repeat([]byte{'A'}, 32)) }()
	conn := &ftpIdleConn{Conn: left, timeout: time.Second, remaining: 16}
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	if err != nil || n != 16 {
		t.Fatal(n, err)
	}
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("reply byte budget not enforced")
	}
	left.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture write blocked")
	}
}
func FuzzFTPURI(f *testing.F) {
	for _, seed := range []string{"ftp://anonymous:pass@localhost/memory.raw", "ftp://host/%2Fabsolute/memory.vmem;type=i", "ftp://host/dir/file%20name.raw", "ftp://host/a%0d%0aSTOR%20x", "ftp://host:65536/x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, location string) {
		parsed, err := parseFTPLocation(location)
		if err != nil {
			return
		}
		display, err := url.Parse(parsed.display)
		if err != nil || display.User != nil || display.RawQuery != "" {
			t.Fatal("invalid sanitized source")
		}
		if strings.ContainsAny(parsed.user+parsed.password+parsed.directory+parsed.file, "\r\n\x00") || parsed.file == "" {
			t.Fatal("command injection accepted")
		}
		host, port, err := net.SplitHostPort(parsed.address)
		if err != nil || host == "" {
			t.Fatal("invalid FTP address", err)
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			t.Fatal("invalid FTP port")
		}
	})
}
