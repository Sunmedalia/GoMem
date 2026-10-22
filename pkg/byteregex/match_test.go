package byteregex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLockedScanner(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, Pattern, Data string
			ChunkSize           int     `json:"chunk_size"`
			Offsets             []int   `json:"scanner_offsets"`
			Error               *string `json:"scanner_error"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 35 {
		t.Fatal("scanner fixture case count changed")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r, err := Compile(c.Pattern, true)
			if c.Error != nil {
				if err == nil {
					t.Fatal("invalid pattern accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := hex.DecodeString(c.Data)
			if err != nil {
				t.Fatal(err)
			}
			limit := c.ChunkSize
			if limit == 0 {
				limit = 16 << 20
			}
			got := []int{}
			want := append([]int{}, c.Offsets...)
			err = r.FindIter(context.Background(), data, limit, Limits{}, func(m Match) error { got = append(got, m.Start+0x1000); return nil })
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("offsets %v; want %v; %v", got, want, err)
			}
		})
	}
}

func TestExecutionBudgetCancellationAndEmitter(t *testing.T) {
	r, err := Compile(`(a+)+$`, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Search(context.Background(), []byte(strings.Repeat("a", 24)+"!"), 0, false, Limits{Steps: 1000})
	if !errors.Is(err, ErrBudget) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.Search(ctx, []byte("aaa"), 0, false, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r, _ = Compile(`|a`, true)
	stop := errors.New("emitter stopped")
	calls := 0
	err = r.FindIter(context.Background(), []byte("aaa"), 10, Limits{}, func(Match) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatal(err, calls)
	}
	ctx, cancel = context.WithCancel(context.Background())
	calls = 0
	err = r.FindIter(ctx, []byte("aaa"), 10, Limits{}, func(Match) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
	// Windows monotonic clocks may not advance between two tiny searches.
	// Force an expired execution deadline instead of assuming nanosecond
	// wall-clock resolution, while exercising the real VM timeout check.
	execution, err := newExecution(context.Background(), []byte("a"), Limits{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	execution.deadline = time.Now().Add(-time.Second)
	if execution.step() || !errors.Is(execution.err, ErrBudget) {
		t.Fatal("expired VM deadline was ignored", execution.err)
	}
}

func TestPythonByteSemantics(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Semantics struct {
			Path, SHA256 string
			Cases        int
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Semantics.Cases < 6000 || fixture.Semantics.Path != "byte-regex-semantics.jsonl" {
		t.Fatal("missing semantic cases")
	}
	raw, err = os.ReadFile("../../internal/engine/testdata/" + fixture.Semantics.Path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != fixture.Semantics.SHA256 {
		t.Fatal("semantic fixture digest differs")
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) != fixture.Semantics.Cases {
		t.Fatal("semantic fixture count differs")
	}
	for i, line := range lines {
		var c struct {
			Pattern, Data string
			Dotall        bool
			Matches       [][2]int
			Error         *string
		}
		if err = json.Unmarshal(line, &c); err != nil {
			t.Fatal(err)
		}
		r, err := Compile(c.Pattern, c.Dotall)
		if c.Error != nil {
			if err == nil {
				t.Errorf("case %d pattern %q: invalid syntax accepted", i, c.Pattern)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %d pattern %q: %v", i, c.Pattern, err)
			continue
		}
		data, _ := hex.DecodeString(c.Data)
		got := [][2]int{}
		err = r.FindIter(context.Background(), data, len(data)+1, Limits{}, func(m Match) error { got = append(got, [2]int{m.Start, m.End}); return nil })
		want := append([][2]int{}, c.Matches...)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("case %d pattern %q data %x dotall=%v: %v, %v; want %v", i, c.Pattern, data, c.Dotall, got, err, want)
		}
	}
}

func TestLongLinearMatchesAndDeadline(t *testing.T) {
	data := []byte(strings.Repeat("a", 128<<10))
	for _, pattern := range []string{`a+`, `.*`, `(a)+\1`, `(aa)+`, strings.Repeat("a", 8192)} {
		r, err := Compile(pattern, true)
		if err != nil {
			t.Fatal(err)
		}
		m, err := r.Search(context.Background(), data, 0, false, Limits{})
		end := len(data)
		if len(pattern) > 100 {
			end = len(pattern)
		}
		if err != nil || m == nil || *m != (Match{0, end}) {
			t.Fatalf("linear match %v %v", m, err)
		}
	}
	r, _ := Compile(`[^x]z`, true)
	large := make([]byte, 16<<20)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := r.Search(ctx, large, 0, false, Limits{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func BenchmarkByteRegexScan(b *testing.B) {
	data := make([]byte, 16<<20)
	copy(data[len(data)-256:], "MATCHMATCH")
	for _, pattern := range []string{`MATCH`, `(MATCH)\1`, `NEVER`} {
		b.Run(pattern, func(b *testing.B) {
			r, err := Compile(pattern, true)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := r.FindIter(context.Background(), data, len(data), Limits{}, func(Match) error { return nil }); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestBoundsCumulativeBudgetAndSharedProgram(t *testing.T) {
	for _, pattern := range []string{`a*?`, `(aa){0,1000}?`} {
		r, _ := Compile(pattern, true)
		m, err := r.Search(context.Background(), []byte(strings.Repeat("a", 4096)), 0, true, Limits{Steps: 32})
		if err != nil || m == nil || *m != (Match{0, 0}) {
			t.Fatalf("lazy repeat scanned unnecessary input: %v %v", m, err)
		}
	}
	for _, pattern := range []string{strings.Repeat("a", 65537), strings.Repeat("(", 129) + strings.Repeat(")", 129), `a{1000001}`, `(?L)a`, string([]byte{255})} {
		if _, err := Compile(pattern, true); err == nil {
			t.Fatalf("unbounded/unsupported pattern accepted: %.30q", pattern)
		}
	}
	r, _ := Compile(``, true)
	calls := 0
	err := r.FindIter(context.Background(), make([]byte, 1000), 1001, Limits{Steps: 1000}, func(Match) error { calls++; return nil })
	if !errors.Is(err, ErrBudget) || calls == 0 || calls >= 1001 {
		t.Fatal(err, calls)
	}
	r, _ = Compile(`(?P<x>[ab]+)-(?P=x)`, true)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				m, err := r.Search(context.Background(), []byte("aba-aba"), 0, false, Limits{})
				if err != nil || m == nil || *m != (Match{0, 7}) {
					t.Errorf("shared program: %v %v", m, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func FuzzByteRegex(f *testing.F) {
	for _, pattern := range []string{`(a+)+$`, `(?P<x>ab)(?P=x)`, `(?<=ab)cd`, `(?:|a)*b`, `[\xff-\x00]`, `(?i:a)`} {
		f.Add(pattern, []byte("aaab ababcd\xff"))
	}
	f.Fuzz(func(t *testing.T, pattern string, data []byte) {
		if len(pattern) > 2048 || len(data) > 2048 {
			t.Skip()
		}
		r, err := Compile(pattern, true)
		if err != nil {
			return
		}
		lastEnd, emptyAt := -1, -1
		err = r.FindIter(context.Background(), data, len(data)+1, Limits{Steps: 20000, Timeout: 10 * time.Millisecond}, func(m Match) error {
			if m.Start < 0 || m.End < m.Start || m.End > len(data) || m.Start < lastEnd {
				t.Fatalf("invalid match %+v after %d", m, lastEnd)
			}
			if m.Start == m.End && m.Start == emptyAt {
				t.Fatalf("repeated empty match %+v", m)
			}
			if m.Start == m.End {
				emptyAt = m.Start
			} else {
				emptyAt = -1
			}
			lastEnd = m.End
			return nil
		})
		if err != nil && !errors.Is(err, ErrBudget) {
			t.Fatal(err)
		}
	})
}
