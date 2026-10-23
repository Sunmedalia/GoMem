package explore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type Session struct {
	Engine *engine.Engine
	Layer  memory.MemoryLayer
}

func New(e *engine.Engine) *Session { return &Session{e, e.Env.Physical} }

const Help = `help                         show commands
plugins                      list native capabilities
run NAME [key=value ...]      run a plugin, with quoted parameter values
hex ADDRESS [LENGTH]          read up to 65536 bytes in current address space
dis ADDRESS [LENGTH] [ARCH]   disassemble x86/x64/arm/arm64 bytes in current space
type TYPE ADDRESS            inspect typed fields (up to 128)
use physical|kernel          select an address space
use process EVIDENCE_ID       select a process using a sealed pslist result
search "LITERAL"             physical literal scan
tasks                        show persisted task status
bookmark EVIDENCE_ID NOTE     save an evidence bookmark
quit                         exit shell
Full volshell compatibility is not implemented.
`

// Split implements quoting without environment expansion, subprocesses or eval.
func Split(s string) ([]string, error) {
	var args []string
	var word strings.Builder
	var quote rune
	escaped, started := false, false
	for _, r := range s {
		if escaped {
			word.WriteRune(r)
			escaped = false
			started = true
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			started = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if unicode.IsSpace(r) {
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		word.WriteRune(r)
		started = true
	}
	if escaped || quote != 0 {
		return nil, fmt.Errorf("unterminated quote or escape")
	}
	if started {
		args = append(args, word.String())
	}
	return args, nil
}
func (s *Session) Execute(ctx context.Context, line string, w io.Writer) error {
	args, err := Split(line)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return nil
	}
	if err = s.Engine.Store.History(ctx, line); err != nil {
		return err
	}
	switch args[0] {
	case "help":
		_, err = io.WriteString(w, Help)
		return err
	case "plugins":
		for _, p := range s.Engine.Registry.List() {
			if _, err = fmt.Fprintf(w, "%s\t%s\n", p.Name, p.Description); err != nil {
				return err
			}
		}
		return nil
	case "tasks":
		tasks, err := s.Engine.Store.Tasks(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(tasks)
	case "use":
		if len(args) == 2 && args[1] == "physical" {
			s.Layer = s.Engine.Env.Physical
			return nil
		}
		if len(args) == 2 && args[1] == "kernel" {
			if s.Engine.Env.Kernel == nil {
				return fmt.Errorf("kernel layer needs --dtb")
			}
			s.Layer = s.Engine.Env.Kernel
			return nil
		}
		if len(args) == 3 && args[1] == "process" {
			return s.process(ctx, args[2])
		}
		return fmt.Errorf("use physical|kernel|process EVIDENCE_ID")
	case "dis", "disasm":
		return s.disassemble(ctx, args, w)
	case "hex":
		if len(args) < 2 || len(args) > 3 {
			return fmt.Errorf("hex ADDRESS [LENGTH]")
		}
		a, err := strconv.ParseUint(args[1], 0, 64)
		if err != nil {
			return err
		}
		n := uint64(256)
		if len(args) == 3 {
			n, err = strconv.ParseUint(args[2], 0, 32)
			if err != nil {
				return err
			}
		}
		if n == 0 || n > 65536 {
			return fmt.Errorf("hex length must be 1..65536")
		}
		b, err := memory.Read(ctx, s.Layer, a, int(n))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s @ %#x\n%s", s.Layer.Name(), a, hex.Dump(b))
		return err
	case "type":
		if len(args) != 3 {
			return fmt.Errorf("type TYPE ADDRESS")
		}
		if s.Engine.Env.Symbols == nil {
			return fmt.Errorf("type inspection needs --symbols")
		}
		if err = s.Engine.Check(ctx, plugin.Spec{Name: "type", NeedsKernel: true, Platform: s.Engine.Env.OS}); err != nil {
			return err
		}
		a, err := strconv.ParseUint(args[2], 0, 64)
		if err != nil {
			return err
		}
		typ, err := s.Engine.Env.Symbols.Type(args[1])
		if err != nil {
			return err
		}
		r := &object.Reader{Layer: s.Layer, Symbols: s.Engine.Env.Symbols}
		names := make([]string, 0, len(typ.Fields))
		for name := range typ.Fields {
			names = append(names, name)
		}
		sort.Strings(names)
		for i, name := range names {
			if i >= 128 {
				_, err = fmt.Fprintln(w, "remaining fields omitted (128-field display limit)")
				return err
			}
			f := typ.Fields[name]
			address, er := memory.Add(a, f.Offset)
			v := evidence.Missing("unreadable", er)
			if er == nil {
				u, er := r.Scalar(ctx, address, f.Type)
				if er != nil {
					v = evidence.Missing("not_scalar_or_unreadable", er)
				} else if f.Type.Kind == "pointer" {
					v = evidence.Address(u)
				} else {
					v = evidence.Number(u)
					ref := f.Type
					for depth := 0; ref.Kind == "bitfield" && ref.Underlying() != nil && depth < 64; depth++ {
						ref = *ref.Underlying()
					}
					if ref.Kind == "enum" {
						en, err := s.Engine.Env.Symbols.Enumeration(ref.Name)
						if err == nil {
							v = evidence.Value{Kind: "enum", Data: map[string]any{"raw": evidence.Number(u).String(), "names": en.Names(u)}}
						}
					} else if base, err := r.ScalarType(f.Type); err == nil && base.Signed {
						signed, err := r.Int(ctx, a, args[1], name)
						if err != nil {
							v = evidence.Missing("unreadable", err)
						} else {
							v = evidence.Integer(signed)
						}
					}
				}
			}
			if _, err = fmt.Fprintf(w, "+%#x %-32s %-12s %s\n", f.Offset, name, f.Type.Kind, render.Safe(v.String())); err != nil {
				return err
			}
		}
		return nil
	case "run", "search":
		name := "generic.ioc"
		params := map[string]string{}
		if args[0] == "search" {
			if len(args) != 2 {
				return fmt.Errorf("search \"LITERAL\"")
			}
			params["needle"] = args[1]
		} else {
			if len(args) < 2 {
				return fmt.Errorf("run NAME [key=value ...]")
			}
			name = args[1]
			for _, arg := range args[2:] {
				k, v, ok := strings.Cut(arg, "=")
				if !ok {
					return fmt.Errorf("parameter must be key=value")
				}
				if _, ok := params[k]; ok {
					return fmt.Errorf("duplicate parameter %s", k)
				}
				params[k] = v
			}
		}
		p, err := s.Engine.Registry.Get(name)
		if err != nil {
			return err
		}
		out, err := render.New(w, "jsonl", p.Spec().Columns)
		if err != nil {
			return err
		}
		res, err := s.Engine.Run(ctx, name, params, engine.RunOptions{Emit: out.Row})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "task %s: %d rows (cached=%t)\n", res.Task.ID, res.Task.Rows, res.Reused)
		return err
	case "bookmark":
		if len(args) < 3 {
			return fmt.Errorf("bookmark EVIDENCE_ID NOTE")
		}
		if _, err = s.Engine.Store.Find(ctx, args[1]); err != nil {
			return err
		}
		return s.Engine.Store.Bookmark(ctx, args[1], strings.Join(args[2:], " "))
	default:
		return fmt.Errorf("unknown exploration command %q; use help", args[0])
	}
}
func (s *Session) process(ctx context.Context, id string) error {
	row, err := s.Engine.Store.Find(ctx, id)
	if err != nil {
		return err
	}
	if err = row.Verify(); err != nil {
		return err
	}
	if row.Provenance.ImageSHA256 != s.Engine.Hash {
		return fmt.Errorf("process evidence belongs to a different image")
	}
	if row.Provenance.Plugin != "windows.pslist" && row.Provenance.Plugin != "linux.pslist" {
		return fmt.Errorf("process selection requires pslist evidence")
	}
	root, err := row.Cells["DTB"].Uint()
	if row.Provenance.Plugin == "linux.pslist" {
		pgd, e := row.Cells["PGDVirtual"].Uint()
		if e != nil {
			return e
		}
		v, ok := s.Engine.Env.Kernel.(*memory.Virtual)
		if !ok {
			return fmt.Errorf("kernel translator unavailable")
		}
		t, e := v.Translator.Translate(ctx, pgd)
		if e != nil {
			return e
		}
		root = t.Physical
		err = nil
	}
	if err != nil {
		return err
	}
	if root == 0 {
		return fmt.Errorf("process root is absent")
	}
	tr, err := memory.NewTranslatorForOS(s.Engine.Env.Physical, root, s.Engine.Config.Arch, s.Engine.Env.OS, 1024)
	if err != nil {
		return err
	}
	s.Layer = &memory.Virtual{Physical: s.Engine.Env.Physical, Translator: tr, ID: "process:" + row.Cells["Identity"].String()}
	return nil
}
