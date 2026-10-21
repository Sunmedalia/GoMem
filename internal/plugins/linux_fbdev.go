package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxFbdevPlugins() []builtin {
	cols := []evidence.Column{}
	for _, n := range []string{"Device", "ID", "Virtual resolution", "State", "RecordType"} {
		cols = append(cols, evidence.Column{Name: n, Kind: "string"})
	}
	for _, n := range []string{"Address", "Offset"} {
		cols = append(cols, evidence.Column{Name: n, Kind: "address"})
	}
	for _, n := range []string{"Size", "BPP", "LineLength"} {
		cols = append(cols, evidence.Column{Name: n, Kind: "uint64"})
	}
	cols = append(cols, evidence.Column{Name: "Filename", Kind: "artifact"}, evidence.Column{Name: "FieldEvidence", Kind: "structure"}, evidence.Column{Name: "Error", Kind: "missing"})
	return []builtin{{plugin.Spec{Name: "linux.fbdev", Upstream: "linux.graphics.fbdev.Fbdev", Platform: "linux", NeedsKernel: true, Description: "Enumerate fbdev framebuffers and extract native PNG or raw buffers", Parameters: []plugin.Parameter{{Name: "dump", Kind: "bool", Default: "false", Description: "Extract framebuffers into the case"}, {Name: "max-framebuffers", Kind: "uint", Default: "256", Description: "Registered framebuffer bound, 1..4096"}, {Name: "max-bytes", Kind: "uint", Default: "67108864", Description: "Cumulative read and per-buffer allocation bound, 1..1073741824"}}, Columns: cols}, linuxFbdev}}
}

type fbBitfield struct{ Offset, Length, Reverse uint64 }
type fbPNGBuffer struct {
	bytes.Buffer
	ctx   context.Context
	limit uint64
}

func (b *fbPNGBuffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > b.limit-uint64(b.Len()) {
		return 0, fmt.Errorf("framebuffer PNG exceeds output allocation bound")
	}
	return b.Buffer.Write(p)
}

type fbReadBudget struct {
	memory.MemoryLayer
	remaining func() uint64
}

func (l *fbReadBudget) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if uint64(len(p)) > l.remaining() {
		return 0, fmt.Errorf("framebuffer acquisition byte budget exhausted")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

// The pinned renderer consumes consecutive little-endian pixels, ignoring line
// padding, and does not scale narrow channels. Preserve that observable behavior.
func fbPixels(ctx context.Context, raw []byte, x, y, bpp, max uint64, fields [4]fbBitfield) (*image.NRGBA, error) {
	if x == 0 || y == 0 || x > max/4 || y > max/(x*4) || x > uint64(^uint(0)>>1) || y > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("framebuffer decoded dimensions exceed allocation bound")
	}
	if bpp == 0 || bpp > 64 || bpp%8 != 0 {
		return nil, fmt.Errorf("unsupported framebuffer bits per pixel %d", bpp)
	}
	for _, f := range fields {
		if f.Offset > 64 || f.Length > 64 || f.Length > 64-f.Offset {
			return nil, fmt.Errorf("invalid framebuffer color field")
		}
	}
	img := image.NewNRGBA(image.Rect(0, 0, int(x), int(y)))
	step := int(bpp / 8)
	cursor := 0
	for i := 0; i < len(img.Pix); i += 4 {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		var pixel uint64
		for j := 0; j < step && cursor+j < len(raw); j++ {
			pixel |= uint64(raw[cursor+j]) << uint(j*8)
		}
		cursor += step
		img.Pix[i+3] = 255
		for c, f := range fields {
			if f.Length == 0 {
				continue
			}
			v := pixel >> f.Offset
			if f.Length < 64 {
				v &= (uint64(1) << f.Length) - 1
			}
			if f.Reverse != 0 {
				var rev uint64
				for k := uint64(0); k < f.Length; k++ {
					rev = rev<<1 | v&1
					v >>= 1
				}
				v = rev
			}
			if v > 255 {
				v = 255
			}
			img.Pix[i+c] = byte(v)
		}
	}
	return img, nil
}

func linuxFbdev(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("fbdev requires kernel memory and symbols")
	}
	dump, err := strconv.ParseBool(p["dump"])
	if err != nil {
		return err
	}
	bound := func(name string, max uint64) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 64)
		if err != nil || n == 0 || n > max {
			return 0, fmt.Errorf("%s must be 1..%d", name, max)
		}
		return n, nil
	}
	maxFB, err := bound("max-framebuffers", 4096)
	if err != nil {
		return err
	}
	maxBytes, err := bound("max-bytes", 1<<30)
	if err != nil {
		return err
	}
	var outputErr error
	send := func(row evidence.Row) error {
		if outputErr != nil {
			return outputErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		outputErr = out(row)
		if outputErr == nil {
			outputErr = ctx.Err()
		}
		return outputErr
	}
	rowAt := func(kind string, at uint64) evidence.Row {
		return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Offset": evidence.Address(at), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", at)}}
	}
	var acquired uint64
	layerName := e.Kernel.Name()
	trace := &linuxIDRLayer{MemoryLayer: &fbReadBudget{MemoryLayer: e.Kernel, remaining: func() uint64 { return maxBytes - acquired }}}
	trace.observe = func(at uint64, raw []byte, want int, cause error) error {
		acquired += uint64(len(raw))
		row := rowAt("framebuffer_read", at)
		proof := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(cause == nil)}
		if cause != nil {
			proof["Error"] = evidence.Missing("read_failed", cause)
			row.Cells["Error"] = proof["Error"]
		}
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
		return send(row)
	}
	e.Kernel = trace
	e.Objects = &object.Reader{Layer: trace, Symbols: e.Symbols}
	number := func(base uint64, typ, path string) (uint64, error) { return e.Objects.Uint(ctx, base, typ, path) }
	pointer := func(base uint64, typ, path string) (uint64, error) {
		f, err := e.Objects.Field(typ, path)
		if err != nil {
			return 0, err
		}
		if f.Type.Kind != "pointer" {
			return 0, fmt.Errorf("%s.%s is not a pointer", typ, path)
		}
		return number(base, typ, path)
	}
	text := func(base uint64, typ, path string) (string, error) {
		f, err := e.Objects.Field(typ, path)
		if err != nil {
			return "", err
		}
		n, err := e.Objects.Size(f.Type)
		if err != nil {
			return "", err
		}
		elementSize := uint64(0)
		if f.Type.Subtype != nil {
			elementSize, err = e.Objects.Size(*f.Type.Subtype)
			if err != nil {
				return "", err
			}
		}
		if f.Type.Kind != "array" || elementSize != 1 || n == 0 || n > 256 {
			return "", fmt.Errorf("invalid %s.%s byte array", typ, path)
		}
		at, err := memory.Add(base, f.Offset)
		if err != nil {
			return "", err
		}
		raw, err := memory.Read(ctx, trace, at, int(n))
		if err != nil {
			return "", err
		}
		return fbString(raw), nil
	}
	countAt, err := e.Symbol("num_registered_fb")
	if err != nil {
		return fmt.Errorf("fbdev count symbol unavailable: %w", err)
	}
	countSymbol, err := e.Symbols.Lookup("num_registered_fb")
	if err != nil {
		return err
	}
	if countSymbol.Type == nil {
		return fmt.Errorf("framebuffer count symbol has no type")
	}
	count, err := e.Objects.Scalar(ctx, countAt, *countSymbol.Type)
	if err != nil {
		return err
	}
	if count > maxFB {
		return fmt.Errorf("registered framebuffer count %d exceeds bound %d", count, maxFB)
	}
	if count == 0 {
		return nil
	}
	registered, err := e.Symbol("registered_fb")
	if err != nil {
		return err
	}
	width := e.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return fmt.Errorf("unsupported pointer width")
	}
	var failures []error
	for i := uint64(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if outputErr != nil {
			return outputErr
		}
		slot, err := memory.Add(registered, i*uint64(width))
		if err != nil {
			return err
		}
		var at uint64
		rawSlot, err := memory.Read(ctx, trace, slot, width)
		if err != nil {
			return err
		}
		at = 0
		for j, b := range rawSlot {
			at |= uint64(b) << uint(j*8)
		}
		row := rowAt("framebuffer", at)
		parse := func() error {
			id, err := text(at, "fb_info", "fix.id")
			if err != nil {
				return err
			}
			if id == "" {
				row.Cells["ID"] = evidence.Missing("not_available", nil)
			} else {
				row.Cells["ID"] = evidence.Text(id)
			}
			read := func(path string) (uint64, error) { return number(at, "fb_info", path) }
			x, err := read("var.xres_virtual")
			if err != nil {
				return err
			}
			y, err := read("var.yres_virtual")
			if err != nil {
				return err
			}
			line, err := read("fix.line_length")
			if err != nil {
				return err
			}
			bpp, err := read("var.bits_per_pixel")
			if err != nil {
				return err
			}
			if line != 0 && y > ^uint64(0)/line {
				return fmt.Errorf("framebuffer size overflow")
			}
			size := y * line
			row.Cells["Size"] = evidence.Number(size)
			row.Cells["BPP"] = evidence.Number(bpp)
			row.Cells["LineLength"] = evidence.Number(line)
			row.Cells["Virtual resolution"] = evidence.Text(fmt.Sprintf("%dx%d", x, y))
			screen, err := pointer(at, "fb_info", "screen_base")
			if err != nil {
				return err
			}
			row.Cells["Address"] = evidence.Address(screen)
			state, err := read("state")
			if err != nil {
				return err
			}
			stateText := "SUSPENDED"
			if state == 0 {
				stateText = "RUNNING"
			}
			row.Cells["State"] = evidence.Text(stateText)
			dev, devErr := pointer(at, "fb_info", "dev")
			if devErr == nil {
				var name uint64
				name, devErr = pointer(dev, "device", "kobj.name")
				if devErr == nil {
					var raw []byte
					raw, devErr = memory.Read(ctx, trace, name, 256)
					if devErr == nil {
						row.Cells["Device"] = evidence.Text(fbString(raw))
					}
				}
			}
			if devErr != nil {
				row.Cells["Device"] = evidence.Missing("device_name_unavailable", devErr)
			}
			if outputErr != nil {
				return outputErr
			}
			gray, err := read("var.grayscale")
			if err != nil {
				return err
			}
			var fields [4]fbBitfield
			if gray <= 1 {
				for c, name := range []string{"red", "green", "blue", "transp"} {
					f := &fields[c]
					f.Offset, err = read("var." + name + ".offset")
					if err != nil {
						return err
					}
					f.Length, err = read("var." + name + ".length")
					if err != nil {
						return err
					}
					f.Reverse, err = read("var." + name + ".msb_right")
					if err != nil {
						return err
					}
				}
			}
			row.Cells["Filename"] = evidence.Text("Disabled")
			if !dump {
				return devErr
			}
			if e.Artifacts == nil {
				return fmt.Errorf("framebuffer extraction requires case artifact storage")
			}
			if size > maxBytes || size > maxBytes-acquired {
				return fmt.Errorf("framebuffer source size exceeds byte budget")
			}
			buffer := make([]byte, int(size))
			for offset := uint64(0); offset < size; {
				n := min(uint64(1<<20), size-offset)
				address, err := memory.Add(screen, offset)
				if err != nil {
					return err
				}
				chunk, err := memory.Read(ctx, trace, address, int(n))
				if err != nil {
					return err
				}
				copy(buffer[int(offset):], chunk)
				offset += n
			}
			extension := "raw"
			if gray <= 1 {
				img, err := fbPixels(ctx, buffer, x, y, bpp, maxBytes, fields)
				if err != nil {
					return err
				}
				encoded := fbPNGBuffer{ctx: ctx, limit: maxBytes}
				if err = png.Encode(&encoded, img); err != nil {
					return err
				}
				buffer = encoded.Bytes()
				extension = "png"
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if id == "" {
				id = "N-A"
			}
			id = strings.Map(func(r rune) rune {
				if r == '/' || r == '\\' || r < 32 {
					return '_'
				}
				return r
			}, id)
			writer, err := e.Artifacts.Create(ctx, evidence.ArtifactRequest{Name: fmt.Sprintf("%s_%dx%d_%dbpp.%s", id, x, y, bpp, extension), Size: uint64(len(buffer)), Layer: layerName, Offset: fmt.Sprintf("0x%x", screen)})
			if err != nil {
				return err
			}
			var writeErr error
			for offset := 0; offset < len(buffer); {
				if writeErr = ctx.Err(); writeErr != nil {
					break
				}
				end := min(offset+1<<20, len(buffer))
				var n int
				n, writeErr = writer.Write(buffer[offset:end])
				if writeErr == nil && n != end-offset {
					writeErr = io.ErrShortWrite
				}
				if writeErr != nil {
					break
				}
				offset = end
			}
			artifact, finishErr := writer.Finish(ctx, writeErr)
			row.Cells["Filename"] = evidence.Value{Kind: "artifact", Data: artifact}
			return errors.Join(devErr, writeErr, finishErr)
		}
		err = parse()
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			failures = append(failures, err)
			row.Cells["Error"] = evidence.Missing("framebuffer_incomplete", err)
			if _, ok := row.Cells["Filename"]; !ok || row.Cells["Filename"].String() == "Disabled" {
				row.Cells["Filename"] = evidence.Missing("extraction_unavailable", err)
			}
		}
		if err := send(row); err != nil {
			return err
		}
	}
	return errors.Join(failures...)
}

func fbString(raw []byte) string {
	text, _ := replaceInvalidUTF8(bytes.SplitN(raw, []byte{0}, 2)[0])
	return strings.SplitN(text, "\ufffd", 2)[0]
}
