package plugins

import (
	"encoding/json"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsVistaDetectionMatchesPinnedDistinguisher(t *testing.T) {
	if windowsVistaOrLater(nil) {
		t.Fatal("nil symbols")
	}
	old := &symbols.ISF{}
	if windowsVistaOrLater(old) {
		t.Fatal("no KdCopyDataBlock")
	}
	vista := &symbols.ISF{Symbols: map[string]symbols.Symbol{"KdCopyDataBlock": {Address: 1}}}
	if !windowsVistaOrLater(vista) {
		t.Fatal("symbol fallback")
	}
	typed := &symbols.ISF{Types: map[string]symbols.Type{"KdCopyDataBlock": {Kind: "void"}}}
	if !windowsVistaOrLater(typed) {
		t.Fatal("type fallback")
	}
	xp := peTable(t, 5, 1, 2600)
	xp.Symbols = map[string]symbols.Symbol{"KdCopyDataBlock": {Address: 1}}
	if windowsVistaOrLater(xp) {
		t.Fatal("PE version must win over the fallback symbol")
	}
	win7 := peTable(t, 6, 1, 7601)
	if !windowsVistaOrLater(win7) {
		t.Fatal("6.1")
	}
	incomplete := &symbols.ISF{Meta: map[string]json.RawMessage{"windows": json.RawMessage(`{"pe":{"major":10,"minor":0}}`)}}
	if windowsVistaOrLater(incomplete) {
		t.Fatal("revision is required before the PE version is trusted")
	}
}

func peTable(t *testing.T, major, minor, revision int) *symbols.ISF {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"pe": map[string]int{"major": major, "minor": minor, "revision": revision}})
	if err != nil {
		t.Fatal(err)
	}
	return &symbols.ISF{Meta: map[string]json.RawMessage{"windows": raw}}
}
