package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type callbackIndexHole struct{ memory.MemoryLayer }

func (l callbackIndexHole) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == 0x201 && len(p) == 1 {
		return 0, io.ErrUnexpectedEOF
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

func TestCallbackPoolActualConstraintsAndHeaders(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-callback-pool-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit  string
		Layouts []struct {
			Width       int
			Vista       bool
			ISF         json.RawMessage
			Data        string
			Constraints []struct {
				Tag         string
				TypeName    string `json:"type_name"`
				PageType    int    `json:"page_type"`
				Size, Index []*uint64
			}
			Cases []struct {
				Offset, Block, Index uint64
				Tag                  string
				PoolType             uint64 `json:"pool_type"`
				Accepted             bool
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Layouts) != 4 {
		t.Fatal("callback oracle drift")
	}
	total := 0
	for _, layout := range fixture.Layouts {
		t.Run(fmt.Sprintf("width%d/vista%t", layout.Width, layout.Vista), func(t *testing.T) {
			constraints, err := callbackPoolConstraints(layout.Width, layout.Vista)
			if err != nil || len(constraints) != len(layout.Constraints) {
				t.Fatal("callback constraints", err)
			}
			lookup := map[string]poolConstraint{}
			for i, want := range layout.Constraints {
				got := constraints[i]
				if hex.EncodeToString(got.tag) != want.Tag || got.typeName != want.TypeName || got.pageType != want.PageType || len(want.Size) != 2 || !got.hasMin || want.Size[0] == nil || got.minSize != *want.Size[0] || got.hasMax != (want.Size[1] != nil) || got.hasMax && got.maxSize != *want.Size[1] {
					t.Fatal("callback factory differs", i, got, want)
				}
				var min, max uint64
				if want.Index != nil {
					if len(want.Index) != 2 {
						t.Fatal("invalid index fixture")
					}
					if want.Index[0] != nil {
						min = *want.Index[0]
					}
					if want.Index[1] != nil {
						max = *want.Index[1]
					}
				}
				if got.minIndex != min || got.maxIndex != max {
					t.Fatal("index endpoints differ")
				}
				lookup[want.Tag] = got
			}
			table, err := symbols.Parse(layout.ISF)
			if err != nil {
				t.Fatal(err)
			}
			data, err := hex.DecodeString(layout.Data)
			if err != nil {
				t.Fatal(err)
			}
			reader := &object.Reader{Layer: flatMemory(data), Symbols: table}
			for _, c := range layout.Cases {
				constraint := lookup[c.Tag]
				index, err := reader.Uint(context.Background(), c.Offset, "_POOL_HEADER", "PoolIndex")
				if err != nil || index != c.Index {
					t.Fatal("index bytes differ", err)
				}
				ok, err := poolIndexOK(context.Background(), reader, c.Offset, constraint)
				if err != nil {
					t.Fatal(err)
				}
				size := uint64(layout.Width*2) * c.Block
				accepted := ok && (!constraint.hasMin || size >= constraint.minSize) && (!constraint.hasMax || size <= constraint.maxSize) && poolPageOK(c.PoolType, constraint.pageType, layout.Vista)
				if accepted != c.Accepted {
					t.Fatal("actual callback scanner differs", c, accepted)
				}
				total++
			}
		})
	}
	if total != 1984 {
		t.Fatal("callback case count", total)
	}
	if _, err := callbackPoolConstraints(16, true); err == nil {
		t.Fatal("unsupported width accepted")
	}
}

func TestCallbackPoolIndexPipelineAndSchema(t *testing.T) {
	for _, index := range []byte{0, 1, 2, 255} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			e, data := poolScannerFixture(t)
			table := e.Symbols.(*symbols.ISF)
			header := table.Types["_POOL_HEADER"]
			header.Fields["PoolIndex"] = symbols.Field{Offset: 1, Type: symbols.TypeRef{Kind: "base", Name: "unsigned char"}}
			table.Types["_POOL_HEADER"] = header
			copy(data[0x204:], []byte("Cbrb"))
			data[0x201] = index
			constraints, _ := callbackPoolConstraints(8, false)
			c := constraints[2]
			c.minIndex, c.maxIndex = 1, 1
			hits := 0
			err := scanPoolObjects(context.Background(), e, []poolConstraint{c}, "callbacks", poolScannerRow, func(evidence.Row) error { return nil }, func(_ context.Context, _ poolHit) (evidence.Row, bool, error) {
				hits++
				return evidence.Row{}, false, nil
			})
			want := 0
			if index == 1 {
				want = 1
			}
			if err != nil || hits != want {
				t.Fatal("index filter not applied by pool pipeline", hits, err)
			}
			faulted := e
			faulted.Kernel = callbackIndexHole{e.Kernel}
			faulted.Objects = &object.Reader{Layer: faulted.Kernel, Symbols: table}
			err = scanPoolObjects(context.Background(), faulted, []poolConstraint{c}, "callbacks", poolScannerRow, func(evidence.Row) error { return nil }, func(_ context.Context, _ poolHit) (evidence.Row, bool, error) {
				t.Fatal("unreadable index became an accepted object")
				return evidence.Row{}, false, nil
			})
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal("unreadable index became clean absence", err)
			}
			delete(header.Fields, "PoolIndex")
			if _, err := poolScanLayout(e, []poolConstraint{c}); err == nil {
				t.Fatal("missing index schema became empty success")
			}
			// A zero endpoint is ignored by the pinned scanner, even when the
			// symbol table has no PoolIndex member to read.
			c.minIndex, c.maxIndex = 0, 0
			if ok, err := poolIndexOK(context.Background(), e.Objects, 0x200, c); err != nil || !ok {
				t.Fatal(ok, err)
			}
		})
	}
}
