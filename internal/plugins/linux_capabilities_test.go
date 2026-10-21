package plugins

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type capabilityLayer []byte

func (b capabilityLayer) Name() string           { return "capability-fixture" }
func (b capabilityLayer) Ranges() []memory.Range { return nil }
func (b capabilityLayer) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a >= uint64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[a:])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}
func capabilityEnvironment(layout, endian string) (plugin.Environment, capabilityLayer) {
	base := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: name} }
	word := base("u32")
	field := symbols.Field{Type: word}
	member := "cap"
	switch layout {
	case "u32_cap_array_1", "u32_cap_array_2":
		count := uint64(1)
		if strings.HasSuffix(layout, "_2") {
			count = 2
		}
		field.Type = symbols.TypeRef{Kind: "array", Count: count, Subtype: &word}
	case "u64_val":
		member, field.Type = "val", base("u64")
	}
	table := &symbols.ISF{Bases: map[string]symbols.Type{
		"u32": {Kind: "int", Size: 4, Endian: endian}, "u64": {Kind: "int", Size: 8, Endian: endian},
	}, Types: map[string]symbols.Type{
		"capability": {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{member: field}},
		"cred":       {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"cap_effective": {Type: symbols.TypeRef{Kind: "struct", Name: "capability"}}}},
	}, Symbols: map[string]symbols.Symbol{}}
	data := make(capabilityLayer, 32)
	e := plugin.Environment{Kernel: data, Symbols: table, Objects: &object.Reader{Layer: data, Symbols: table}}
	return e, data
}

func TestLinuxCapabilityPinnedDecoder(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-capability-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Names []string
		Cases []struct {
			Layout            string
			Last              *uint64
			Raw, Masked, Text string
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Cases) != 1680 || strings.Join(oracle.Names, " ") != strings.Join(linuxCapabilityNames, " ") {
		t.Fatal(err)
	}
	for i, c := range oracle.Cases {
		for _, endian := range []string{"little", "big"} {
			e, data := capabilityEnvironment(c.Layout, endian)
			value, err := strconv.ParseUint(c.Raw, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			var order binary.ByteOrder = binary.LittleEndian
			if endian == "big" {
				order = binary.BigEndian
			}
			if c.Layout == "u64_val" {
				order.PutUint64(data[8:], value)
			} else {
				order.PutUint32(data[8:], uint32(value))
				order.PutUint32(data[12:], uint32(value>>32))
			}
			last := uint64(40)
			if c.Last != nil {
				last = *c.Last
			}
			text, capture, err := linuxReadCapability(context.Background(), e, 8, "cap_effective", last)
			if err != nil || text.Kind != "string" || text.String() != c.Text {
				t.Fatal(i, c, text, err)
			}
			details := capture.Data.(map[string]evidence.Value)
			masked, err := details["Masked"].Uint()
			expected, parseErr := strconv.ParseUint(c.Masked, 0, 64)
			if err != nil || parseErr != nil || masked != expected {
				t.Fatal(i, details, err)
			}
		}
	}
}

func TestLinuxCapabilityReadFailuresAndLimit(t *testing.T) {
	ctx := context.Background()
	for _, scenario := range []string{"missing", "array-zero", "array-three", "array-width", "signed", "val-width", "noninteger", "partial", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			e, data := capabilityEnvironment("u32_cap_array_2", "little")
			table := e.Symbols.(*symbols.ISF)
			cap := table.Types["capability"]
			f := cap.Fields["cap"]
			ctx := ctx
			switch scenario {
			case "missing":
				delete(cap.Fields, "cap")
			case "array-zero":
				f.Type.Count = 0
			case "array-three":
				cap.Size = 12
				f.Type.Count = 3
			case "array-width":
				f.Type.Subtype.Name = "u64"
				cap.Size = 16
			case "signed":
				b := table.Bases["u32"]
				b.Signed = true
				table.Bases["u32"] = b
			case "val-width":
				delete(cap.Fields, "cap")
				cap.Fields["val"] = symbols.Field{Type: symbols.TypeRef{Kind: "base", Name: "u32"}}
			case "noninteger":
				f.Type = symbols.TypeRef{Kind: "pointer"}
			case "partial":
				e.Kernel = data[:12]
				e.Objects.Layer = e.Kernel
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if scenario != "missing" && scenario != "val-width" {
				cap.Fields["cap"] = f
			}
			table.Types["capability"] = cap
			cred := table.Types["cred"]
			cred.Size = cap.Size
			table.Types["cred"] = cred
			text, capture, err := linuxReadCapability(ctx, e, 8, "cap_effective", 40)
			if err == nil || text.Kind != "missing" || text.Error == "" {
				t.Fatal(text, capture, err)
			}
			if scenario == "partial" && capture.Kind != "structure" {
				t.Fatal("partial bytes lost", capture)
			}
		})
	}
	for _, scenario := range []string{"fallback", "symbol", "big-endian", "missing-type", "unreadable", "negative", "too-large"} {
		t.Run(scenario, func(t *testing.T) {
			e, data := capabilityEnvironment("u64_val", "little")
			table := e.Symbols.(*symbols.ISF)
			typ := symbols.TypeRef{Kind: "base", Name: "u32"}
			if scenario != "fallback" {
				table.Symbols["cap_last_cap"] = symbols.Symbol{Address: 16, Type: &typ}
			}
			last := uint32(35)
			if scenario == "negative" {
				last = ^uint32(0)
			}
			if scenario == "too-large" {
				last = 4096
			}
			binary.LittleEndian.PutUint32(data[16:], last)
			if scenario == "big-endian" {
				b := table.Bases["u32"]
				b.Endian = "big"
				table.Bases["u32"] = b
				binary.BigEndian.PutUint32(data[16:], last)
			}
			if scenario == "missing-type" {
				table.Symbols["cap_last_cap"] = symbols.Symbol{Address: 16}
			}
			if scenario == "unreadable" {
				e.Kernel = data[:16]
			}
			got, _, err := linuxCapabilityLimit(ctx, e)
			valid := scenario == "fallback" || scenario == "symbol" || scenario == "big-endian"
			if valid && (err != nil || got != 35 && scenario != "fallback" || got != 40 && scenario == "fallback") || !valid && err == nil {
				t.Fatal(got, err)
			}
		})
	}
	if err := linuxCapabilities(ctx, plugin.Environment{}, nil, nil); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
