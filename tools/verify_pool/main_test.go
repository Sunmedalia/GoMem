package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type data []byte

func (d data) Name() string           { return "physical" }
func (d data) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(d))}} }
func (d data) ReadAt(_ context.Context, p []byte, at uint64) (int, error) {
	if at > uint64(len(d)) {
		return 0, io.EOF
	}
	n := copy(p, d[at:])
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func TestCaptureRejectsFalseBytesDigestsAndCompleteness(t *testing.T) {
	layer := data("original")
	for _, mode := range []string{"valid", "raw", "digest", "captured", "complete", "layer", "offset", "invalid-offset"} {
		t.Run(mode, func(t *testing.T) {
			digest := sha256.Sum256(layer)
			row := evidence.Row{Provenance: evidence.Provenance{Layer: layer.Name(), Offset: "0x0"}, Cells: map[string]evidence.Value{"Layer": evidence.Text(layer.Name()), "Offset": evidence.Address(0), "Requested": evidence.Number(8), "Captured": evidence.Number(8), "ReadComplete": evidence.Bool(true), "Raw": evidence.Bytes(layer), "SHA256": evidence.Text(hex.EncodeToString(digest[:]))}}
			switch mode {
			case "raw":
				row.Cells["Raw"] = evidence.Bytes([]byte("forged!!"))
			case "digest":
				row.Cells["SHA256"] = evidence.Text("wrong")
			case "captured":
				row.Cells["Captured"] = evidence.Number(7)
			case "complete":
				row.Cells["ReadComplete"] = evidence.Bool(false)
			case "layer":
				row.Cells["Layer"] = evidence.Text("wrong")
			case "offset":
				row.Provenance.Offset = "0x1"
			case "invalid-offset":
				row.Provenance.Offset = "invalid"
			}
			err := capture(row, map[string]memory.MemoryLayer{layer.Name(): layer})
			if (err != nil) != (mode != "valid") {
				t.Fatal(mode, err)
			}
		})
	}
}
