package yara

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestYaraActualPinnedScannerOracle(t *testing.T) {
	library := nativeLibrary(t)
	data, err := os.ReadFile("testdata/yarax-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	type referenceMatch struct {
		Offset        uint64
		Rule, Pattern string
		Bytes         []byte
	}
	type referenceRule struct{ Namespace, Rule string }
	var fixture struct {
		Cases []struct {
			Source        string
			Data          []byte
			Matches       []referenceMatch
			MatchingRules []referenceRule `json:"matching_rules"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 75 {
		t.Fatal("incomplete actual scanner oracle")
	}
	for n, tc := range fixture.Cases {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			rules, err := Compile(context.Background(), library, []byte(tc.Source))
			if err != nil {
				t.Fatal(err)
			}
			defer rules.Close()
			matches, err := rules.Scan(context.Background(), tc.Data, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got := []referenceMatch{}
			gotRules := []referenceRule{}
			seen := map[referenceRule]bool{}
			for _, m := range matches {
				r := referenceRule{Namespace: m.Namespace, Rule: m.Rule}
				if !seen[r] {
					seen[r] = true
					gotRules = append(gotRules, r)
				}
				if !m.RuleOnly {
					got = append(got, referenceMatch{Offset: m.Offset, Rule: m.Namespace + "." + m.Rule, Pattern: m.Pattern, Bytes: m.Bytes})
				}
			}
			if !reflect.DeepEqual(got, tc.Matches) || !reflect.DeepEqual(gotRules, tc.MatchingRules) {
				t.Fatalf("native actual scanner differs: got=%+v rules=%+v want=%+v rules=%+v", got, gotRules, tc.Matches, tc.MatchingRules)
			}
		})
	}
}

func nativeLibrary(t testing.TB) string {
	t.Helper()
	path := os.Getenv("GOMEM_YARAX_LIBRARY")
	if path == "" || !Supported() {
		t.Skip("set GOMEM_YARAX_LIBRARY for actual native YARA-X")
	}
	return path
}

func TestYaraActualCompilationAndMatches(t *testing.T) {
	library := nativeLibrary(t)
	source := []byte(`rule literal { strings: $a = "AbCd" nocase condition: $a } rule no_strings { condition: true }`)
	rules, err := Compile(context.Background(), library, source)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Close()
	data := []byte("xxABCDyyabcd")
	matches, err := rules.Scan(context.Background(), data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	instances, only := 0, 0
	for _, m := range matches {
		if m.Namespace != "default" {
			t.Fatal(m)
		}
		if m.RuleOnly {
			only++
			if m.Rule != "no_strings" || m.Pattern != "" {
				t.Fatal(m)
			}
			continue
		}
		instances++
		if m.Rule != "literal" || m.Pattern != "$a" || (m.Offset != 2 && m.Offset != 8) || m.Length != 4 || !bytes.Equal(m.Bytes, data[m.Offset:m.Offset+m.Length]) {
			t.Fatal(m)
		}
	}
	if instances != 2 || only != 1 {
		t.Fatal(matches)
	}
	for _, options := range []Options{{MaxMatches: 1}, {MaxOutputBytes: 1}} {
		if results, err := rules.Scan(context.Background(), data, options); !errors.Is(err, ErrLimit) || results != nil {
			t.Fatal("result budget silently truncates", results, err)
		}
	}
	if _, err := rules.Scan(context.Background(), nil, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := rules.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Scan(context.Background(), data, Options{}); err == nil {
		t.Fatal("closed rules reused")
	}
	for _, source := range []string{`rule broken { condition: }`, `include "unexpected-file.yar"`} {
		_, err := Compile(context.Background(), library, []byte(source))
		var compileErr *CompileError
		if !errors.As(err, &compileErr) || len(compileErr.Diagnostics) == 0 {
			t.Fatal("missing structured diagnostics", err)
		}
	}
}

func TestYaraValidationAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		path   string
		source []byte
	}{{"relative", []byte("rule r {condition:true}")}, {"/missing", nil}, {"/missing", []byte{0xff}}, {"/missing", []byte{'a', 0}}, {"/missing", make([]byte, MaxSource+1)}} {
		if rules, err := Compile(context.Background(), tc.path, tc.source); err == nil {
			rules.Close()
			t.Fatal("invalid input accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Compile(ctx, "/missing", []byte("rule r {condition:true}")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	library := nativeLibrary(t)
	r, err := Compile(context.Background(), library, []byte("rule r {condition:true}"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Scan(ctx, nil, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.Scan(context.Background(), make([]byte, MaxScan+1), Options{}); err == nil {
		t.Fatal("scan input budget ignored")
	}
	if _, err := r.Scan(context.Background(), nil, Options{TimeoutSeconds: 61}); err == nil {
		t.Fatal("timeout budget ignored")
	}
}

func TestYaraNativeTimeoutAndWarnings(t *testing.T) {
	library := nativeLibrary(t)
	rules, err := Compile(context.Background(), library, []byte(`import "math" rule slow {condition:for any i in (0..1000000000):(math.entropy(0,filesize)==i+100)}`))
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Close()
	if len(rules.Warnings()) == 0 || string(rules.Warnings()) == "[]" {
		t.Fatal("slow rule warning was discarded")
	}
	if results, err := rules.Scan(context.Background(), make([]byte, 4096), Options{TimeoutSeconds: 1}); !errors.Is(err, ErrTimeout) || results != nil {
		t.Fatal("native timeout became successful results", results, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if results, err := rules.Scan(ctx, make([]byte, 4096), Options{}); !errors.Is(err, context.DeadlineExceeded) || results != nil {
		t.Fatal("deadline became successful partial results", results, err)
	}
}

func TestYaraConcurrentRulesAndClose(t *testing.T) {
	library := nativeLibrary(t)
	rules, err := Compile(context.Background(), library, []byte(`rule r {strings:$a="test" condition:$a}`))
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Close()
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 10; n++ {
				matches, err := rules.Scan(context.Background(), []byte("test"), Options{})
				if err != nil || len(matches) != 1 {
					t.Error(matches, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := rules.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Scan(context.Background(), nil, Options{}); err == nil {
		t.Fatal("closed rules accepted")
	}
}

func FuzzYaraNativeScan(f *testing.F) {
	library := nativeLibrary(f)
	rules, err := Compile(context.Background(), library, []byte(`rule patterns {strings:$a="needle" nocase $b={00 ?? [1-8] FF} $c=/ab+c/ condition:any of them}`))
	if err != nil {
		f.Fatal(err)
	}
	defer rules.Close()
	f.Add([]byte("needle abbcc"))
	f.Add([]byte{0, 1, 2, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		matches, err := rules.Scan(context.Background(), data, Options{TimeoutSeconds: 1, MaxMatches: 1000, MaxOutputBytes: 1 << 20})
		if errors.Is(err, ErrLimit) || errors.Is(err, ErrTimeout) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			if m.RuleOnly {
				continue
			}
			if m.Offset > uint64(len(data)) || m.Length > uint64(len(data))-m.Offset || !bytes.Equal(m.Bytes, data[m.Offset:m.Offset+m.Length]) {
				t.Fatal(m)
			}
		}
	})
}
