package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestPoolHeadersActualPinnedScanner(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-pool-header-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit      string
		Constraints []struct {
			Tag        string
			TypeName   string `json:"type_name"`
			ObjectType string `json:"object_type"`
			PageType   int    `json:"page_type"`
			Size       []*uint64
			SkipType   bool `json:"skip_type"`
			Additional []string
		}
		Layouts []struct {
			Width int
			Vista bool
			ISF   json.RawMessage
			Data  string
			Cases []struct {
				Offset, Block                   uint64
				Tag                             string
				PoolType                        uint64 `json:"pool_type"`
				Accepted, Free, Paged, Nonpaged bool
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	constraints, err := builtinPoolConstraints()
	if err != nil || fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Constraints) != 15 || len(fixture.Layouts) != 4 || len(constraints) != 15 {
		t.Fatal("fixture drift", err)
	}
	lookup := map[string]poolConstraint{}
	for i, want := range fixture.Constraints {
		got := constraints[i]
		if hex.EncodeToString(got.tag) != want.Tag || got.typeName != want.TypeName || got.objectType != want.ObjectType || got.pageType != want.PageType || got.skipType != want.SkipType || !reflect.DeepEqual(append([]string{}, got.additional...), want.Additional) {
			t.Fatal("constraint drift", i, got, want)
		}
		if len(want.Size) != 2 || (want.Size[0] != nil) != got.hasMin || (want.Size[1] != nil) != got.hasMax || got.hasMin && got.minSize != *want.Size[0] || got.hasMax && got.maxSize != *want.Size[1] {
			t.Fatal("constraint size drift", i)
		}
		lookup[want.Tag] = got
	}
	for _, layout := range fixture.Layouts {
		t.Run(fmt.Sprintf("width%d/vista%t", layout.Width, layout.Vista), func(t *testing.T) {
			table, err := symbols.Parse(layout.ISF)
			if err != nil {
				t.Fatal(err)
			}
			data, err := hex.DecodeString(layout.Data)
			if err != nil {
				t.Fatal(err)
			}
			reader := &object.Reader{Layer: flatMemory(data), Symbols: table}
			alignment, err := poolAlignment(layout.Width)
			if err != nil {
				t.Fatal(err)
			}
			if len(layout.Cases) != 360 {
				t.Fatal("case drift", len(layout.Cases))
			}
			for _, c := range layout.Cases {
				block, err := reader.Uint(context.Background(), c.Offset, "_POOL_HEADER", "BlockSize")
				if err != nil {
					t.Fatal(err)
				}
				poolType, err := reader.Uint(context.Background(), c.Offset, "_POOL_HEADER", "PoolType")
				if err != nil {
					t.Fatal(err)
				}
				tag, err := reader.Uint(context.Background(), c.Offset, "_POOL_HEADER", "PoolTag")
				if err != nil {
					t.Fatal(err)
				}
				if block != c.Block || poolType != c.PoolType || fmt.Sprintf("%02x%02x%02x%02x", byte(tag), byte(tag>>8), byte(tag>>16), byte(tag>>24)) != c.Tag {
					t.Fatal("header decoding drift", c)
				}
				for _, test := range []struct {
					mask int
					want bool
				}{{poolFree, c.Free}, {poolPaged, c.Paged}, {poolNonPaged, c.Nonpaged}} {
					if poolPageOK(poolType, test.mask, layout.Vista) != test.want {
						t.Fatal("pool classification drift", c, test)
					}
				}
				constraint := lookup[c.Tag]
				size := alignment * block
				accepted := (!constraint.hasMin || size >= constraint.minSize) && (!constraint.hasMax || size <= constraint.maxSize) && poolPageOK(poolType, constraint.pageType, layout.Vista)
				if accepted != c.Accepted {
					t.Fatal("actual scanner differs", c, accepted)
				}
			}
		})
	}
}
