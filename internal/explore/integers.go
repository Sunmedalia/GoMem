package explore

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func (s *Session) displayIntegers(ctx context.Context, args []string, w io.Writer) error {
	if len(args) < 2 || len(args) > 4 {
		return fmt.Errorf("db|dw|dd|dq ADDRESS [BYTE_LENGTH] [le|be|native]")
	}
	address, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return err
	}
	length := uint64(128)
	if len(args) >= 3 {
		length, err = strconv.ParseUint(args[2], 0, 32)
		if err != nil {
			return err
		}
	}
	if length > 65536 {
		return fmt.Errorf("integer display byte length must be 0..65536")
	}
	if _, err := memory.Add(address, length); err != nil {
		return err
	}
	width := 1
	switch args[0] {
	case "dw", "display_words":
		width = 2
	case "dd", "display_doublewords":
		width = 4
	case "dq", "display_quadwords":
		width = 8
	}
	// Portable little endian is the forensic default, independent of host ISA.
	var order binary.ByteOrder = binary.LittleEndian
	orderName := "le"
	if len(args) == 4 {
		switch args[3] {
		case "le", "<":
		case "be", ">", "!":
			order = binary.BigEndian
			orderName = "be"
		case "native", "@", "=":
			order = binary.NativeEndian
			orderName = "native"
		default:
			return fmt.Errorf("byte order must be le, be or native")
		}
	}
	if err := s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	data, err := memory.Read(ctx, s.Layer, address, int(length))
	if err != nil {
		return err
	}
	if err := s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s @ %#x (%d-byte integers; %s; %d bytes requested)\n", s.Layer.Name(), address, width, orderName, length); err != nil {
		return err
	}
	if err := writeIntegerLines(ctx, w, address, data, width, order); err != nil {
		return err
	}
	if tail := len(data) % width; tail != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := len(data) - tail
		if _, err := fmt.Fprintf(w, "%#x: %d trailing bytes cannot form a %d-byte integer: %x\n", address+uint64(start), tail, width, data[start:]); err != nil {
			return err
		}
	}
	return s.Engine.ValidateSource(ctx)
}

// writeIntegerLines renders complete values. The shell separately retains any
// short final value, rather than silently discarding its original bytes.
func writeIntegerLines(ctx context.Context, w io.Writer, address uint64, data []byte, width int, order binary.ByteOrder) error {
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return fmt.Errorf("unsupported integer width")
	}
	complete := len(data) - len(data)%width
	for offset := 0; offset < complete; offset += 16 {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := data[offset:min(offset+16, complete)]
		values := make([]string, 0, 16/width)
		ascii := make([]string, 0, len(line)/width)
		for at := 0; at < len(line); at += width {
			var value uint64
			switch width {
			case 1:
				value = uint64(line[at])
			case 2:
				value = uint64(order.Uint16(line[at:]))
			case 4:
				value = uint64(order.Uint32(line[at:]))
			case 8:
				value = order.Uint64(line[at:])
			}
			text := fmt.Sprintf("%0*x", width*2, value)
			values = append(values, text)
			// The pinned shell derives ASCII from the displayed numeric hex,
			// so little-endian multi-byte groups appear reversed intentionally.
			decoded, _ := hex.DecodeString(text)
			for n, b := range decoded {
				if b <= 32 || b >= 127 {
					decoded[n] = '.'
				}
			}
			ascii = append(ascii, string(decoded))
		}
		for n := len(line) / width; n < 16/width; n++ {
			values = append(values, strings.Repeat(" ", width*2))
		}
		connector := " "
		if width == 1 {
			connector = ""
		}
		if _, err := fmt.Fprintf(w, "%#x    %s    %s\n", address+uint64(offset), strings.Join(values, " "), strings.Join(ascii, connector)); err != nil {
			return err
		}
	}
	return ctx.Err()
}
