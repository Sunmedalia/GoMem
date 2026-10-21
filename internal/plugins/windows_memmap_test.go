package plugins

import "testing"

func TestSingleProcessID(t *testing.T) {
	all, label, err := singleProcessID("  ")
	if err != nil || all != nil || label != "all" {
		t.Fatal(all, label, err)
	}
	one, label, err := singleProcessID("0x10")
	if err != nil || !one[16] || label != "0x10" {
		t.Fatal(one, label, err)
	}
	if _, _, err = singleProcessID("1,2"); err == nil {
		t.Fatal("accepted a comma separated pid")
	}
	if _, _, err = singleProcessID("nope"); err == nil {
		t.Fatal("accepted a non integer")
	}
}
