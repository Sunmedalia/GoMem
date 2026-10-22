package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestDeprecatedHiddenModuleAlias(t *testing.T) {
	if engine.DeprecatedPluginAliases["linux.hidden_modules.Hidden_modules"] != "linux.hidden_modules" || len(engine.DeprecatedPluginAliases) != 24 {
		t.Fatal(len(engine.DeprecatedPluginAliases))
	}
	f := modxFixture(t, "x64", "legacy", "")
	withDwarf2JSON(t, f, "0.9.0")
	e := openModx(t, f, "x64")
	verifyDeprecatedPluginAlias(t, e, "linux.hidden_modules", "linux.hidden_modules.Hidden_modules", 3)
}

func TestDeprecatedNetfilterAlias(t *testing.T) {
	for _, kind := range []string{"list", "entries", "split"} {
		t.Run(kind, func(t *testing.T) {
			e := netfilterLayoutEngine(t, kind, true, "")
			verifyDeprecatedPluginAlias(t, e, "linux.netfilter", "linux.netfilter.Netfilter", 0)
		})
	}
}

func verifyDeprecatedPluginAlias(t *testing.T, e *engine.Engine, native, alias string, expectedRows int64) {
	t.Helper()
	ctx := context.Background()
	var direct, aliased bytes.Buffer
	var directRows, aliasRows []evidence.Row
	decode := func(row evidence.Row, buf *bytes.Buffer, rows *[]evidence.Row) error {
		*rows = append(*rows, row)
		return json.NewEncoder(buf).Encode(row)
	}
	first, err := e.Run(ctx, native, nil, engine.RunOptions{Emit: func(row evidence.Row) error { return decode(row, &direct, &directRows) }})
	if err != nil || expectedRows > 0 && first.Task.Rows != expectedRows {
		t.Fatal(first, err)
	}
	second, err := e.Run(ctx, alias, nil, engine.RunOptions{Emit: func(row evidence.Row) error { return decode(row, &aliased, &aliasRows) }})
	if err != nil || second.Reused || second.Task.Rows != first.Task.Rows || second.Task.Plugin != alias || second.Task.Provenance.Plugin != alias {
		t.Fatal(second, err)
	}
	for i, row := range aliasRows {
		if err = row.Verify(); err != nil || row.Cells["RequestedPlugin"].String() != alias || row.Cells["ImplementedPlugin"].String() != native || row.Provenance.Plugin != alias {
			t.Fatal(i, row, err)
		}
		cells := maps.Clone(row.Cells)
		delete(cells, "RequestedPlugin")
		delete(cells, "ImplementedPlugin")
		if !reflect.DeepEqual(cells, directRows[i].Cells) {
			t.Fatal(row, directRows[i])
		}
	}
	var replayBytes bytes.Buffer
	replay, err := e.Run(ctx, alias, nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replayBytes).Encode(row) }})
	if err != nil || !replay.Reused || replay.Task.ID != second.Task.ID || replay.Task.Plugin != second.Task.Plugin || !bytes.Equal(aliased.Bytes(), replayBytes.Bytes()) {
		t.Fatal(replay, err)
	}
	tasks, err := e.Store.Tasks(ctx)
	if err != nil || len(tasks) != 2 {
		t.Fatal(tasks, err)
	}
	for _, task := range tasks {
		if task.Plugin != task.Provenance.Plugin {
			t.Fatal("task/provenance plugin identity differs", task)
		}
	}

}

func TestDeprecatedMalfindAlias(t *testing.T) {
	e := malfindEngine(t, "x64", "list", "")
	verifyDeprecatedPluginAlias(t, e, "linux.malfind", "linux.malfind.Malfind", 10)
}

func TestDeprecatedWindowsMalfindAlias(t *testing.T) {
	for _, c := range windowsMalfindCases(t) {
		if c.Width == 8 && c.Name == "rwx-private-short" {
			e, _ := windowsMalfindEngine(t, c)
			verifyDeprecatedPluginAlias(t, e, "windows.malfind", "windows.malfind.Malfind", 0)
			return
		}
	}
	t.Fatal("missing fixture")
}
