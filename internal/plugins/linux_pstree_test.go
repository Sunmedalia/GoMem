package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestLinuxPsTreePinnedHierarchy(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-pstree-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Name  string
			Nodes []struct{ TID, TGID, PPID, Address uint64 }
			Rows  []struct {
				TID, Depth     uint64
				GeneratorDepth int  `json:"generator_depth"`
				ParentRow      *int `json:"parent_row"`
			}
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Cases) != 19 {
		t.Fatal(err)
	}
	for _, tc := range oracle.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var input []linuxTreeNode
			for _, n := range tc.Nodes {
				input = append(input, linuxTreeNode{n.TID, n.TGID, n.PPID, n.Address})
			}
			rows, _, err := arrangeLinuxTree(context.Background(), input, 10000)
			if err != nil || len(rows) != len(tc.Rows) {
				t.Fatal(rows, tc.Rows, err)
			}
			for i, want := range tc.Rows {
				got := rows[i]
				if got.TID != want.TID || got.Depth != want.Depth || got.GeneratorDepth != want.GeneratorDepth || got.HasParent != (want.ParentRow != nil) {
					t.Fatal(got, want)
				}
				if want.ParentRow != nil && got.Parent != tc.Rows[*want.ParentRow].TID {
					t.Fatal(got, want)
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err = arrangeLinuxTree(ctx, []linuxTreeNode{{TID: 1}}, 100); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err = arrangeLinuxTree(context.Background(), []linuxTreeNode{{TID: 1, TGID: 1, Address: 0x1000}}, 1); err == nil {
		t.Fatal("work bound not enforced")
	}
}

func FuzzLinuxPsTreeHierarchy(f *testing.F) {
	f.Add([]byte{1, 1, 0, 1, 2, 2, 0, 2, 3, 3, 1, 3})
	f.Add([]byte{1, 1, 2, 1, 2, 2, 1, 2})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 512 {
			raw = raw[:512]
		}
		var nodes []linuxTreeNode
		for i := 0; i+3 < len(raw); i += 4 {
			nodes = append(nodes, linuxTreeNode{TID: uint64(raw[i]), TGID: uint64(raw[i+1]), PPID: uint64(raw[i+2]), Address: uint64(raw[i+3]) * 0x100})
		}
		rows, _, _ := arrangeLinuxTree(context.Background(), nodes, 4096)
		seen := map[uint64]linuxTreeItem{}
		for _, row := range rows {
			if _, exists := seen[row.TID]; exists {
				t.Fatal("repeated tree row", row)
			}
			if row.HasParent {
				parent, ok := seen[row.Parent]
				if !ok || row.Depth != parent.Depth+1 {
					t.Fatal("invalid renderer parent", row)
				}
			} else if row.Depth != 0 {
				t.Fatal("root depth", row)
			}
			seen[row.TID] = row
		}
		if len(rows) > len(nodes) {
			t.Fatal("unbounded output")
		}
	})
}
