package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestDeprecatedHiddenModuleAlias(t *testing.T) {
	if engine.DeprecatedPluginAliases["linux.hidden_modules.Hidden_modules"] != "linux.hidden_modules" || len(engine.DeprecatedPluginAliases) != 21 {
		t.Fatal(len(engine.DeprecatedPluginAliases))
	}
	f := modxFixture(t, "x64", "legacy", "")
	withDwarf2JSON(t, f, "0.9.0")
	e := openModx(t, f, "x64")
	ctx := context.Background()
	var direct, aliased bytes.Buffer
	var directRows, aliasRows []evidence.Row
	decode := func(row evidence.Row, buf *bytes.Buffer, rows *[]evidence.Row) error {
		*rows = append(*rows, row)
		return json.NewEncoder(buf).Encode(row)
	}
	first, err := e.Run(ctx, "linux.hidden_modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return decode(row, &direct, &directRows) }})
	if err != nil || first.Task.Rows != 3 {
		t.Fatal(first, err)
	}
	second, err := e.Run(ctx, "linux.hidden_modules.Hidden_modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return decode(row, &aliased, &aliasRows) }})
	if err != nil || second.Reused || second.Task.Rows != 3 || second.Task.Plugin != "linux.hidden_modules.Hidden_modules" || second.Task.Provenance.Plugin != "linux.hidden_modules.Hidden_modules" {
		t.Fatal(second, err)
	}
	for i, row := range aliasRows {
		if err = row.Verify(); err != nil || row.Cells["RequestedPlugin"].String() != "linux.hidden_modules.Hidden_modules" || row.Cells["ImplementedPlugin"].String() != "linux.hidden_modules" || row.Provenance.Plugin != "linux.hidden_modules.Hidden_modules" {
			t.Fatal(i, row, err)
		}
		if row.Cells["Module Name"].String() != directRows[i].Cells["Module Name"].String() || row.Cells["RecordType"].String() != directRows[i].Cells["RecordType"].String() {
			t.Fatal(row, directRows[i])
		}
	}
	var replayBytes bytes.Buffer
	replay, err := e.Run(ctx, "linux.hidden_modules.Hidden_modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replayBytes).Encode(row) }})
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
