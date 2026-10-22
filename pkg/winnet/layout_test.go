package winnet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

const boundedSchema = `{"metadata":{"format":"6.0.0"},"base_types":{"pointer":{"kind":"int","size":8,"endian":"little"},"u64":{"kind":"int","size":8,"endian":"little"},"be16":{"kind":"int","size":2,"endian":"big"}},"user_types":{"_N":{"kind":"struct","size":1,"fields":{"Zero":{"offset":0,"type":{"kind":"base","name":"u64"}},"Value":{"offset":16,"type":{"kind":"base","name":"u64"}},"Port":{"offset":24,"type":{"kind":"base","name":"be16"}},"Huge":{"offset":0,"type":{"kind":"array","count":18446744073709551615,"subtype":{"kind":"base","name":"u64"}}}}}},"symbols":{},"enums":{}}`

func TestIPAddressUsesDeclaredMemberCoordinates(t *testing.T) {
	layout, err := Parse([]byte(boundedSchema))
	if err != nil {
		t.Fatal(err)
	}
	layout.table.Bases["u8"] = symbols.Type{Kind: "int", Size: 1, Endian: "little"}
	byteType := symbols.TypeRef{Kind: "base", Name: "u8"}
	layout.table.Types["_IN_ADDR"] = symbols.Type{Kind: "struct", Size: 1, Fields: map[string]symbols.Field{
		"addr4": {Offset: 8, Type: symbols.TypeRef{Kind: "array", Count: 4, Subtype: &byteType}},
		"addr6": {Offset: 16, Type: symbols.TypeRef{Kind: "array", Count: 16, Subtype: &byteType}},
	}}
	data := make(original, 32)
	copy(data[8:], []byte{192, 0, 2, 7})
	data[16], data[17], data[18], data[19], data[31] = 0x20, 0x01, 0x0d, 0xb8, 1
	o := Object{Layout: layout, Layer: data}
	for family, want := range map[uint64]string{2: "192.0.2.7", 23: "2001:db8::1"} {
		got, err := o.ip(context.Background(), 0, family)
		if err != nil || got != want {
			t.Fatal("address member offset lost", got, want, err)
		}
	}
}

func TestDeclaredAllocationAndBoundedOriginalFieldReads(t *testing.T) {
	layout, err := Parse([]byte(boundedSchema))
	if err != nil {
		t.Fatal(err)
	}
	data := make(original, 32)
	binary.LittleEndian.PutUint64(data[16:], 0xfedcba9876543210)
	binary.BigEndian.PutUint16(data[24:], 5353)
	o := Object{Layout: layout, Layer: data, Type: "_N"}
	if n, err := layout.DeclaredSize("_N"); err != nil || n != 1 {
		t.Fatal("declared size changed", n, err)
	}
	if n, err := o.Scalar(context.Background(), "Value"); err != nil || n != 0xfedcba9876543210 {
		t.Fatal("original field lost", n, err)
	}
	if n, err := o.Scalar(context.Background(), "Port"); err != nil || n != 5353 {
		t.Fatal("network byte order lost", n, err)
	}
	for _, path := range []string{"Huge", "Absent", "Value.Child", strings.Repeat("x.", 65)} {
		if _, err := o.Scalar(context.Background(), path); err == nil {
			t.Fatal("invalid extent accepted", path)
		}
	}
	for _, data := range [][]byte{nil, []byte("{}"), []byte(boundedSchema + "{}"), []byte(strings.Replace(boundedSchema, `"offset":16`, `"offset":1048577`, 1)), []byte(strings.Replace(boundedSchema, `"size":8`, `"size":16`, 1))} {
		if _, err := Parse(data); err == nil {
			t.Fatal("malformed layout accepted")
		}
	}
}

func TestTruncatedCancelledAndOverflowingReadsRemainErrors(t *testing.T) {
	layout, err := Parse([]byte(boundedSchema))
	if err != nil {
		t.Fatal(err)
	}
	o := Object{Layout: layout, Layer: original(make([]byte, 20)), Type: "_N"}
	if _, err := o.Scalar(context.Background(), "Value"); err == nil {
		t.Fatal("truncated value became zero")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.Scalar(ctx, "Zero"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel hidden", err)
	}
	o.Address = ^uint64(0) - 3
	if _, err := o.Scalar(context.Background(), "Zero"); err == nil {
		t.Fatal("read end overflow accepted")
	}
	if _, err := o.Scalar(context.Background(), "Value"); err == nil {
		t.Fatal("field address overflow accepted")
	}
	if _, err := (Object{}).Scalar(context.Background(), "Zero"); err == nil {
		t.Fatal("nil object accepted")
	}
	if _, err := (Object{}).ListenerSockets(context.Background()); err == nil {
		t.Fatal("nil listener accepted")
	}
}

func FuzzNetworkLayout(f *testing.F) {
	f.Add([]byte(boundedSchema), uint64(0), "Value")
	f.Add([]byte(boundedSchema), ^uint64(0)-3, "Zero")
	f.Add([]byte("{}"), uint64(0), "")
	f.Fuzz(func(t *testing.T, payload []byte, address uint64, path string) {
		if len(payload) > 65536 || len(path) > 256 {
			return
		}
		layout, err := Parse(payload)
		if err != nil {
			return
		}
		o := Object{Layout: layout, Layer: original(make([]byte, 64)), Address: address, Type: "_N"}
		_, _ = o.Scalar(context.Background(), path)
		_, _ = o.Family(context.Background())
		_, _ = o.State(context.Background())
		_, _, _ = o.TCPAddresses(context.Background())
		_, _ = o.ListenerSockets(context.Background())
	})
}

type original []byte

func (m original) Name() string           { return "original" }
func (m original) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(m))}} }
func (m original) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at >= uint64(len(m)) {
		return 0, io.EOF
	}
	n := copy(p, m[at:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

type relocated struct {
	original
	base uint64
}

func (m relocated) Name() string { return "native-virtual" }
func (m relocated) Ranges() []memory.Range {
	return []memory.Range{{Start: m.base, Length: uint64(len(m.original))}}
}
func (m relocated) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at < m.base {
		return 0, io.EOF
	}
	return m.original.ReadAt(ctx, p, at-m.base)
}

func TestPhysicalAllocationUsesNativePointerAddressSpace(t *testing.T) {
	layout, err := Parse([]byte(boundedSchema))
	if err != nil {
		t.Fatal(err)
	}
	layout.table.Bases["u8"] = symbols.Type{Kind: "int", Size: 1, Endian: "little"}
	ptr := func(name string) symbols.TypeRef {
		return symbols.TypeRef{Kind: "pointer", Subtype: &symbols.TypeRef{Kind: "struct", Name: name}}
	}
	byteType := symbols.TypeRef{Kind: "base", Name: "u8"}
	layout.table.Types["_ROOT"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{
		"InetAF": {Offset: 0, Type: ptr("_INETAF")}, "AddrInfo": {Offset: 8, Type: ptr("_ADDRINFO")}, "LocalAddr": {Offset: 16, Type: ptr("_LOCAL_ADDRESS")},
	}}
	layout.table.Types["_INETAF"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"AddressFamily": {Type: symbols.TypeRef{Kind: "base", Name: "u64"}}}}
	layout.table.Types["_ADDRINFO"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Local": {Type: ptr("_LOCAL_ADDRESS")}, "Remote": {Offset: 8, Type: ptr("_IN_ADDR")}}}
	ipRef := ptr("_IN_ADDR")
	layout.table.Types["_LOCAL_ADDRESS"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"pData": {Type: symbols.TypeRef{Kind: "pointer", Subtype: &ipRef}}}}
	layout.table.Types["_IN_ADDR"] = symbols.Type{Kind: "struct", Size: 6, Fields: map[string]symbols.Field{
		"addr4": {Type: symbols.TypeRef{Kind: "array", Count: 4, Subtype: &byteType}}, "addr6": {Type: symbols.TypeRef{Kind: "array", Count: 16, Subtype: &byteType}},
	}}
	physical := make(original, 24)
	for at, value := range map[int]uint64{0: 0x1000, 8: 0x1010, 16: 0x1020} {
		binary.LittleEndian.PutUint64(physical[at:], value)
	}
	native := make(original, 0x60)
	for at, value := range map[int]uint64{0: 2, 0x10: 0x1020, 0x18: 0x1050, 0x20: 0x1030, 0x30: 0x1040} {
		binary.LittleEndian.PutUint64(native[at:], value)
	}
	copy(native[0x40:], []byte{10, 4, 3, 2})
	copy(native[0x50:], []byte{192, 0, 2, 1})
	o := Object{Layout: layout, Layer: physical, Native: relocated{native, 0x1000}, Type: "_ROOT"}
	ctx := context.Background()
	if family, err := o.Family(ctx); err != nil || family != 2 {
		t.Fatal("wrong family space", family, err)
	}
	if local, remote, err := o.TCPAddresses(ctx); err != nil || local != "10.4.3.2" || remote != "192.0.2.1" {
		t.Fatal("wrong TCP pointer space", local, remote, err)
	}
	if sockets, err := o.ListenerSockets(ctx); err != nil || len(sockets) != 1 || sockets[0] != (Socket{"v4", "10.4.3.2", "0.0.0.0"}) {
		t.Fatal("wrong listener pointer space", sockets, err)
	}
	o.Native = nil
	if _, err := o.Family(ctx); err == nil {
		t.Fatal("physical pointer target silently accepted")
	}
}

// These controls require the exact external layout files, not a reconstructed
// copy of their field offsets. CI runs this explicitly after fetching baseline.
func TestActualNetworkObjectMethods(t *testing.T) {
	root := os.Getenv("GOMEM_BASELINE_DIR")
	if root == "" {
		t.Skip("requires pinned GOMEM_BASELINE_DIR; no acceptance established by skip")
	}
	raw, err := os.ReadFile("../../internal/plugins/testdata/windows-network-object-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit  string
		Layouts []struct {
			Name          string
			SourceSHA256  string            `json:"source_sha256"`
			DeclaredSizes map[string]uint64 `json:"declared_sizes"`
		}
		Cases []struct {
			Layout, Type, Scenario string
			Family                 uint64
			Size                   int
			ObjectOffset           uint64 `json:"object_offset"`
			Writes                 []struct {
				Offset int
				Data   string
			}
			Observations struct {
				Family        *uint64
				Local, Remote *string
				LocalPort     uint64 `json:"local_port"`
				RemotePort    uint64 `json:"remote_port"`
				Port          uint64
				State         json.RawMessage
				Sockets       json.RawMessage
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Layouts) != 25 || len(fixture.Cases) != 1200 {
		t.Fatal("fixture drift")
	}
	layouts := map[string]*Layout{}
	for _, source := range fixture.Layouts {
		data, err := os.ReadFile(filepath.Join(root, "volatility3/framework/symbols/windows/netscan", source.Name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != source.SourceSHA256 {
			t.Fatal("source layout digest mismatch")
		}
		layout, err := Parse(data)
		if err != nil {
			t.Fatal(source.Name, err)
		}
		if layout.Digest() != source.SourceSHA256 {
			t.Fatal("lost original source identity")
		}
		pin, ok := catalogPins[source.Name]
		if !ok || pin.sha256 != source.SourceSHA256 || pin.width != layout.PointerSize() {
			t.Fatal("compiled catalog differs from original layout", source.Name)
		}
		for typ, want := range source.DeclaredSizes {
			got, err := layout.DeclaredSize(typ)
			if err != nil || got != want {
				t.Fatal("allocation size changed", typ, got, want, err)
			}
		}
		layouts[source.Name] = layout
	}
	for _, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%s/%s/%s/%d", c.Layout, c.Type, c.Scenario, c.Family), func(t *testing.T) {
			data := make(original, c.Size)
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset+len(b) > len(data) {
					t.Fatal("invalid original write")
				}
				copy(data[w.Offset:], b)
			}
			o := Object{Layout: layouts[c.Layout], Layer: data, Address: c.ObjectOffset, Type: c.Type}
			ctx := context.Background()
			family, err := o.Family(ctx)
			if c.Observations.Family == nil {
				if err == nil {
					t.Fatal("family fault hidden")
				}
			} else if err != nil || family != *c.Observations.Family {
				t.Fatal("family differs", family, err)
			}
			if c.Type == "_TCP_ENDPOINT" {
				local, remote, err := o.TCPAddresses(ctx)
				for name, pair := range map[string]struct {
					Got  string
					Want *string
				}{"local": {local, c.Observations.Local}, "remote": {remote, c.Observations.Remote}} {
					if pair.Want == nil {
						if pair.Got != "" || err == nil {
							t.Fatal("lost unavailable address", name, pair.Got, err)
						}
					} else if pair.Got != *pair.Want {
						t.Fatal("address differs", name, pair.Got, *pair.Want, err)
					}
				}
				for name, want := range map[string]uint64{"LocalPort": c.Observations.LocalPort, "RemotePort": c.Observations.RemotePort} {
					got, err := o.Scalar(ctx, name)
					if err != nil || got != want {
						t.Fatal("port differs", name, got, want, err)
					}
				}
				state, err := o.State(ctx)
				var want string
				if json.Unmarshal(c.Observations.State, &want) == nil {
					if err != nil || state != want {
						t.Fatal("state differs", state, want, err)
					}
				} else if !errors.Is(err, ErrInvalidState) {
					t.Fatal("invalid state hidden", state, err)
				}
			} else {
				port, err := o.Scalar(ctx, "Port")
				if err != nil || port != c.Observations.Port {
					t.Fatal("listener port differs", port, err)
				}
				got, err := o.ListenerSockets(ctx)
				var want [][3]string
				if json.Unmarshal(c.Observations.Sockets, &want) != nil {
					if !errors.Is(err, ErrClassExtension) {
						t.Fatal("class extension fault hidden", err)
					}
				} else {
					actual := make([][3]string, len(got))
					for i, s := range got {
						actual[i] = [3]string{s.Version, s.Local, s.Remote}
					}
					if !reflect.DeepEqual(actual, want) {
						t.Fatal("socket expansion differs", actual, want, err)
					}
					if (c.Scenario == "missing-local" || c.Scenario == "missing-family") && err == nil {
						t.Fatal("fallback discarded original read failure")
					}
				}
			}
			owner, err := o.Scalar(ctx, "Owner")
			wantOwner := uint64(0x6000)
			if c.Scenario == "null-owner" {
				wantOwner = 0
			}
			if err != nil || owner != wantOwner {
				t.Fatal("owner coordinate differs", owner, wantOwner, err)
			}
			created, err := o.Scalar(ctx, "CreateTime.QuadPart")
			wantTime := uint64(133801632000000000)
			if c.Scenario == "zero-time" {
				wantTime = 0
			}
			if err != nil || created != wantTime {
				t.Fatal("original creation time differs", created, wantTime, err)
			}
		})
	}
}
