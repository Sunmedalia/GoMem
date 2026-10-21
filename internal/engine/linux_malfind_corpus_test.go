package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxMalfindNegativeWithPageCoverage(t *testing.T) {
	dir, ref, obs := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_MALFIND_REFERENCE"), os.Getenv("GOMEM_MALFIND_OBSERVATIONS")
	if dir == "" || ref == "" || obs == "" {
		t.Skip("requires corpus and both unmodified and delegated reference prefixes; not acceptance")
	}
	type manifest struct {
		Baseline     struct{ Commit string }
		Image        string `json:"image_sha256"`
		Output       string `json:"output_sha256"`
		PluginOutput string `json:"plugin_output_sha256"`
		Probe        string `json:"probe_sha256"`
		Plugin       string
	}
	load := func(prefix string) manifest {
		raw, err := os.ReadFile(prefix + ".manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		var m manifest
		if err = json.Unmarshal(raw, &m); err != nil || m.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" {
			t.Fatal(m, err)
		}
		return m
	}
	check := func(path, expected string) []byte {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != expected {
			t.Fatal("reference digest differs", path)
		}
		return raw
	}
	unmodified, observed := load(ref), load(obs)
	if unmodified.Plugin != "linux.malware.malfind" || unmodified.Image != observed.Image {
		t.Fatal(unmodified, observed)
	}
	var reference []json.RawMessage
	if err := json.Unmarshal(check(ref+".json", unmodified.Output), &reference); err != nil || len(reference) != 0 {
		t.Fatal("expected pinned negative control", err)
	}
	if err := json.Unmarshal(check(obs+".plugin.json", observed.PluginOutput), &reference); err != nil || len(reference) != 0 {
		t.Fatal("delegated output differs", err)
	}
	check("../../tools/reference_malfind_observations.py", observed.Probe)
	var observations []struct {
		PID, Start, End, Probes, MissingPages, DirtyPages, FirstMissing, LastMissing uint64
		StateDigest                                                                  string
	}
	if err := json.Unmarshal(check(obs+".json", observed.Output), &observations); err != nil || len(observations) != 3192 {
		t.Fatal(err, len(observations))
	}
	key := func(pid, start, end uint64) string { return fmt.Sprintf("%d/%x/%x", pid, start, end) }
	indices := map[string]int{}
	for i, row := range observations {
		k := key(row.PID, row.Start, row.End)
		if _, ok := indices[k]; ok {
			t.Fatal("duplicate reference mapping", k)
		}
		indices[k] = i
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != unmodified.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	var fresh, again bytes.Buffer
	scans, findings, incomplete, captures := 0, 0, 0, 0
	var probes, missing uint64
	result, err := e.Run(context.Background(), "linux.malfind", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		if row.Cells["RecordType"].String() == "malfind_region" {
			findings++
			return nil
		}
		if row.Cells["RecordType"].String() != "dirty_scan" {
			t.Fatal("unexpected record", row)
		}
		scans++
		uintCell := func(cell evidence.Value) uint64 {
			n, err := cell.Uint()
			if err != nil {
				t.Fatal(cell, err)
			}
			return n
		}
		k := key(uintCell(row.Cells["PID"]), uintCell(row.Cells["Start"]), uintCell(row.Cells["End"]))
		index, ok := indices[k]
		if !ok {
			t.Fatal("unexpected or repeated scan", k)
		}
		delete(indices, k)
		want := observations[index]
		fields := bashProofFields(t, row.Cells["FieldEvidence"])
		for field, n := range map[string]uint64{"Probes": want.Probes, "MissingPages": want.MissingPages, "DirtyPages": want.DirtyPages, "FirstMissing": want.FirstMissing, "LastMissing": want.LastMissing} {
			if uintCell(fields[field]) != n {
				t.Fatal(k, field, fields[field], n)
			}
		}
		if fields["StateDigest"].String() != want.StateDigest || fields["Completed"].Data != (want.MissingPages == 0) {
			t.Fatal("page state differs", k, fields, want)
		}
		probes += want.Probes
		missing += want.MissingPages
		if want.MissingPages > 0 {
			incomplete++
			if row.Cells["Error"].Reason != "dirty_scan_incomplete" {
				t.Fatal(row)
			}
		}
		for _, field := range []string{"VMA", "Process", "Flags", "File"} {
			captures += verifyModuleParameterWireCaptures(t, e, fields[field])
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err == nil || result.Task.State != "failed" || scans != 3192 || findings != 0 || len(indices) != 0 || probes != 210847 || missing != 149562 || incomplete != 2880 || captures != 15960 {
		t.Fatal(result, err, scans, findings, len(indices), probes, missing, incomplete, captures)
	}
	rerun, err := e.Run(context.Background(), "linux.malfind", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&again).Encode(row) }})
	if err == nil || rerun.Reused || rerun.Task.ID == result.Task.ID || !bytes.Equal(fresh.Bytes(), again.Bytes()) {
		t.Fatal("incomplete scan must be retried, preserving evidence", rerun, err)
	}
	t.Logf("0 findings; %d VMAs/%d probes match pinned state digests; %d unavailable pages in %d incomplete scans; %d raw captures reread", scans, probes, missing, incomplete, captures)
}
