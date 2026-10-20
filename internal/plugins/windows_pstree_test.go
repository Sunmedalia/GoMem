package plugins

import "testing"

func TestArrangePsTreeParentsAndFilter(t *testing.T) {
	nodes := []psTreeNode{
		{PID: 1, PPID: 0, Included: false},
		{PID: 2, PPID: 1, Included: false},
		{PID: 3, PPID: 1, Included: true},
		{PID: 4, PPID: 3, Included: false},
		{PID: 5, PPID: 1, Included: false},
	}
	got := arrangePsTree(nodes)
	want := []psTreeEmit{
		{PID: 1, Depth: 0},
		{PID: 3, Depth: 1, Parent: 1, HasParent: true},
		{PID: 4, Depth: 2, Parent: 3, HasParent: true},
	}
	if len(got) != len(want) {
		t.Fatalf("rows %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d got %#v want %#v", i, got[i], want[i])
		}
	}
}

func TestArrangePsTreeOmitsSelfParentAndKeepsCycleRoots(t *testing.T) {
	self := arrangePsTree([]psTreeNode{{PID: 9, PPID: 9, Included: true}})
	if len(self) != 0 {
		t.Fatalf("self parent emitted %#v", self)
	}
	cycle := arrangePsTree([]psTreeNode{
		{PID: 10, PPID: 20, Included: true},
		{PID: 20, PPID: 10, Included: true},
	})
	if len(cycle) != 2 || cycle[0].HasParent || cycle[1].HasParent {
		t.Fatalf("cycle %#v", cycle)
	}
	if cycle[0].PID != 10 || cycle[0].Depth != 0 || cycle[1].PID != 20 || cycle[1].Depth != 0 {
		t.Fatalf("cycle order %#v", cycle)
	}
}

func TestArrangePsTreeSiblingOrderFollowsActiveList(t *testing.T) {
	nodes := []psTreeNode{
		{PID: 4, PPID: 0, Included: true},
		{PID: 72, PPID: 4, Included: true},
		{PID: 384, PPID: 4, Included: true},
		{PID: 1292, PPID: 4, Included: true},
	}
	got := arrangePsTree(nodes)
	var children []uint64
	for _, row := range got {
		if row.HasParent && row.Parent == 4 {
			children = append(children, row.PID)
		}
	}
	if len(children) != 3 || children[0] != 72 || children[1] != 384 || children[2] != 1292 {
		t.Fatalf("children %v", children)
	}
}
