package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxSockscanPlugins() []builtin {
	columns := []evidence.Column{}
	for _, p := range [][2]string{{"Offset", "address"}, {"Family", "string"}, {"Type", "string"}, {"Proto", "string"}, {"Source", "string"}, {"SourcePort", "string"}, {"Destination", "string"}, {"DestinationPort", "string"}, {"State", "string"}, {"Filter", "string"}, {"FamilyRaw", "uint64"}, {"TypeRaw", "uint64"}, {"ProtocolRaw", "uint64"}, {"StateRaw", "uint64"}, {"Hit", "address"}, {"FileOffset", "address"}, {"VirtualSocket", "address"}, {"CandidateSource", "string"}, {"CandidateAssessment", "string"}, {"DedupKey", "string"}, {"RecordType", "string"}, {"FieldEvidence", "structure"}, {"Coverage", "structure"}, {"Error", "missing"}} {
		columns = append(columns, evidence.Column{Name: p[0], Kind: p[1]})
	}
	return []builtin{{plugin.Spec{Name: "linux.sockscan", Upstream: "linux.sockscan.Sockscan", Platform: "linux", NeedsKernel: true, Description: "Scan physical socket/file-operation pointer candidates, preserving native kernel pointer targets and acquisition evidence", Columns: columns, Parameters: []plugin.Parameter{
		{Name: "baseline-ipv6", Kind: "bool", Default: "false", Description: "Reproduce pinned IPv6 pointer-derived address reads in the original physical layer; failures remain evidence"},
		{Name: "max-candidates", Kind: "uint", Default: "1000000", Description: "Total matching pointer candidate bound, 1..1000000"},
		{Name: "max-scan-bytes", Kind: "uint", Default: "1099511627776", Description: "Physical scan byte bound, 1..17592186044416"},
		{Name: "max-bytes", Kind: "uint", Default: "268435456", Description: "Object acquisition byte bound, 1..1073741824"},
		{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-namespace/device list node bound, 1..1000000"},
	}}, linuxSockscan}}
}

var errSocketReadBudget = errors.New("socket acquisition byte budget exhausted")

type socketReadBudget struct {
	memory.MemoryLayer
	s *linuxSocketScan
}

func (b *socketReadBudget) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if b.s.outputErr != nil {
		return 0, b.s.outputErr
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > b.s.maxBytes-b.s.acquired {
		return 0, errSocketReadBudget
	}
	return b.MemoryLayer.ReadAt(ctx, p, at)
}

type linuxSocketNeedle struct {
	file, destruct bool
	symbols        []string
}
type linuxSocketScan struct {
	baselineIPv6                                                                                 bool
	ctx                                                                                          context.Context
	e                                                                                            plugin.Environment
	out                                                                                          plugin.Emit
	translator                                                                                   memory.Translator
	physical, native                                                                             memory.MemoryLayer
	maxBytes, acquired, reads, maxCandidates, candidates, scanned, sockets, suppressed, rejected uint64
	maxNodes                                                                                     int
	outputErr                                                                                    error
	failures                                                                                     pluginFailures
	devices                                                                                      map[int64]string
	devicesLoaded                                                                                bool
	devicesErr                                                                                   error
}

func (s *linuxSocketScan) emit(r evidence.Row) error {
	if s.outputErr != nil {
		return s.outputErr
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	s.outputErr = s.out(r)
	if s.outputErr == nil {
		s.outputErr = s.ctx.Err()
	}
	return s.outputErr
}
func (s *linuxSocketScan) row(at uint64, kind string) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind)}, Provenance: evidence.Provenance{Layer: s.e.Physical.Name(), Offset: fmt.Sprintf("0x%x", at)}}
}
func (s *linuxSocketScan) trace(layer memory.MemoryLayer) memory.MemoryLayer {
	return &linuxIDRLayer{MemoryLayer: &socketReadBudget{MemoryLayer: layer, s: s}, observe: func(at uint64, raw []byte, want int, cause error) error {
		s.acquired += uint64(len(raw))
		s.reads++
		r := s.row(at, "socket_read")
		r.Provenance.Layer = layer.Name()
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(raw), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(cause == nil), "ReadIndex": evidence.Number(s.reads)}}
		if cause != nil {
			s.failures.add(cause)
			r.Cells["Error"] = evidence.Missing("read_failed", cause)
		}
		return s.emit(r)
	}}
}
func (s *linuxSocketScan) view(data memory.MemoryLayer, at uint64, typ string) (object.View, error) {
	return object.NewView(data, s.native, s.e.Symbols, at, typ)
}
func socketScanLimit(p map[string]string, name string, maximum uint64) (uint64, error) {
	v, err := strconv.ParseUint(p[name], 0, 64)
	if err != nil || v == 0 || v > maximum {
		return 0, fmt.Errorf("%s must be 1..%d", name, maximum)
	}
	return v, nil
}
func linuxSockscan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Physical == nil || e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("sockscan requires physical memory, kernel and symbols")
	}
	if _, err := linuxModuleAddressMask(e); err != nil {
		return err
	}
	kernel, ok := e.Kernel.(*memory.Virtual)
	if !ok || kernel.Translator == nil {
		return fmt.Errorf("sockscan requires a kernel translator")
	}
	s := &linuxSocketScan{ctx: ctx, e: e, out: out, translator: kernel.Translator, devices: map[int64]string{}}
	var err error
	s.baselineIPv6, err = strconv.ParseBool(p["baseline-ipv6"])
	if err != nil {
		return err
	}
	if s.maxBytes, err = socketScanLimit(p, "max-bytes", 1<<30); err != nil {
		return err
	}
	if s.maxCandidates, err = socketScanLimit(p, "max-candidates", 1000000); err != nil {
		return err
	}
	maxScan, err := socketScanLimit(p, "max-scan-bytes", 1<<44)
	if err != nil {
		return err
	}
	maxNodes, err := socketScanLimit(p, "max-nodes", 1000000)
	if err != nil {
		return err
	}
	s.maxNodes = int(maxNodes)
	s.physical, s.native = s.trace(e.Physical), s.trace(e.Kernel)
	needles := map[uint64]linuxSocketNeedle{}
	for _, group := range []struct {
		names []string
		file  bool
	}{{[]string{"socket_file_ops", "sockfs_dentry_operations"}, true}, {[]string{"sock_def_destruct", "packet_sock_destruct", "unix_sock_destructor", "netlink_sock_destruct", "inet_sock_destruct"}, false}} {
		for _, name := range group.names {
			at, er := e.Symbol(name)
			if er != nil {
				continue
			}
			// ISF symbols may use a masked 48-bit address; pointer storage is canonical.
			if e.Architecture == "x64" && at&(1<<47) != 0 && at>>48 == 0 {
				at |= 0xffff000000000000
			}
			if e.Symbols.PointerSize() == 4 && at > 0xffffffff {
				return fmt.Errorf("socket symbol %s exceeds pointer width", name)
			}
			n := needles[at]
			n.file = n.file || group.file
			n.destruct = n.destruct || !group.file
			n.symbols = append(n.symbols, name)
			needles[at] = n
		}
	}
	if len(needles) == 0 {
		return fmt.Errorf("socket file/destructor symbols unavailable; scan cannot establish empty results")
	}
	fop, err := e.Objects.Field("file", "f_op")
	if err != nil {
		return err
	}
	destruct, err := e.Objects.Field("sock", "sk_destruct")
	if err != nil {
		return err
	}
	seen := map[uint64]bool{}
	seenFile := false
	err = s.scan(e.Physical, needles, maxScan, func(hit, value uint64) error {
		if s.candidates >= s.maxCandidates {
			return fmt.Errorf("socket candidate limit exhausted")
		}
		s.candidates++
		n := needles[value]
		r := s.row(hit, "socket_candidate")
		r.Cells["Hit"] = evidence.Address(hit)
		source := "destructor"
		if n.file {
			source = "file"
		}
		if n.file && n.destruct {
			source = "destructor+file"
		}
		r.Cells["CandidateSource"] = evidence.Text(source)
		matched := make([]byte, e.Symbols.PointerSize())
		if len(matched) == 4 {
			binary.LittleEndian.PutUint32(matched, uint32(value))
		} else {
			binary.LittleEndian.PutUint64(matched, value)
		}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Needle": evidence.Address(value), "RootType": evidence.Text("sock"), "RootDataLayer": evidence.Text(s.physical.Name()), "NativeLayer": evidence.Text(s.native.Name()), "MatchedBytes": evidence.Bytes(matched), "Symbols": {Kind: "structure", Data: n.symbols}}}
		beforeReads := s.reads
		finish := func() error {
			proof := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
			proof["FirstReadIndex"] = evidence.Number(beforeReads + 1)
			proof["ReadCount"] = evidence.Number(s.reads - beforeReads)
			return s.emit(r)
		}
		var root object.View
		var cause error
		key := uint64(0)
		if n.destruct {
			if hit < destruct.Offset {
				cause = fmt.Errorf("socket destructor container underflow")
			} else {
				key = hit - destruct.Offset
				root, cause = s.view(s.physical, key, "sock")
			}
		}
		if n.file {
			// Independent source branches match pinned precedence. The pinned
			// key is None for every file-only hit, set before field extraction.
			if hit < fop.Offset {
				cause = fmt.Errorf("socket file container underflow")
			} else {
				r.Cells["FileOffset"] = evidence.Address(hit - fop.Offset)
				var virtual uint64
				root, virtual, cause = s.fileSocket(hit - fop.Offset)
				if virtual != 0 {
					r.Cells["VirtualSocket"] = evidence.Address(virtual)
				}
			}
		}
		if cause != nil {
			s.rejected++
			if errors.Is(cause, object.ErrNullPointer) {
				r.Cells["CandidateAssessment"] = evidence.Text("null_pointer_rejected")
				r.Cells["Error"] = evidence.Missing("candidate_rejected_null_pointer", nil)
				r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)["Rejection"] = evidence.Text(cause.Error())
			} else {
				s.failures.add(cause)
				r.Cells["Error"] = evidence.Missing("candidate_unreadable", cause)
			}
			if er := finish(); er != nil {
				return er
			}
			if errors.Is(cause, errSocketReadBudget) {
				return cause
			}
			return nil
		}
		duplicate := false
		if n.destruct {
			r.Cells["DedupKey"] = evidence.Text(fmt.Sprintf("0x%x", key))
			duplicate = seen[key]
			seen[key] = true
		} else {
			r.Cells["DedupKey"] = evidence.Text("baseline:file-none")
			duplicate = seenFile
			seenFile = true
		}
		r.Cells["Offset"] = evidence.Address(root.Address())
		if duplicate {
			s.suppressed++
			r.Cells["CandidateAssessment"] = evidence.Text("baseline_duplicate")
			return finish()
		}
		var terminal error
		if er := s.extract(root, &r); er != nil {
			s.rejected++
			if errors.Is(er, errSocketReadBudget) {
				terminal = er
			}
			if errors.Is(er, object.ErrNullPointer) {
				r.Cells["CandidateAssessment"] = evidence.Text("null_pointer_rejected")
				r.Cells["Error"] = evidence.Missing("candidate_rejected_null_pointer", nil)
				r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)["Rejection"] = evidence.Text(er.Error())
			} else {
				s.failures.add(er)
				r.Cells["Error"] = evidence.Missing("socket_decoding_incomplete", er)
			}
			r.Cells["RecordType"] = evidence.Text("socket_candidate")
		} else if r.Cells["RecordType"].String() == "socket" {
			s.sockets++
		} else {
			s.suppressed++
		}
		if er := finish(); er != nil {
			return er
		}
		return terminal
	})
	if s.outputErr != nil {
		return s.outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	cause := errors.Join(err, s.failures.err("physical socket scan"))
	r := s.row(0, "socket_scan_summary")
	r.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"ScanBytes": evidence.Number(s.scanned), "Candidates": evidence.Number(s.candidates), "Sockets": evidence.Number(s.sockets), "Suppressed": evidence.Number(s.suppressed), "ObjectReads": evidence.Number(s.reads), "ObjectBytes": evidence.Number(s.acquired), "PhysicalScanComplete": evidence.Bool(err == nil), "Rejected": evidence.Number(s.rejected), "CandidateFailureEvents": evidence.Number(uint64(s.failures.count)), "Completed": evidence.Bool(cause == nil)}}
	if cause != nil {
		r.Cells["Error"] = evidence.Missing("scan_incomplete", cause)
	}
	if er := s.emit(r); er != nil {
		return er
	}
	return cause
}
func (s *linuxSocketScan) fileSocket(at uint64) (object.View, uint64, error) {
	file, err := s.view(s.physical, at, "file")
	if err != nil {
		return object.View{}, 0, err
	}
	path := "f_path.dentry"
	if _, err = file.Field(path); errors.Is(err, object.ErrFieldAbsent) {
		path = "f_dentry"
	} else if err != nil {
		return object.View{}, 0, err
	}
	dentry, err := file.Dereference(s.ctx, path)
	if err != nil {
		return object.View{}, 0, err
	}
	inode, err := dentry.Dereference(s.ctx, "d_inode")
	if err != nil {
		return object.View{}, 0, err
	}
	alloc, err := inode.Container("socket_alloc", "vfs_inode")
	if err != nil {
		return object.View{}, 0, err
	}
	socket, err := alloc.Embedded("socket")
	if err != nil {
		return object.View{}, 0, err
	}
	root, err := socket.Dereference(s.ctx, "sk")
	if err != nil {
		return object.View{}, 0, err
	}
	translation, err := s.translator.Translate(s.ctx, root.Address())
	if err != nil {
		return object.View{}, root.Address(), err
	}
	physical, err := s.view(s.physical, translation.Physical, "sock")
	return physical, root.Address(), err
}

// scan checks each byte position once, in physical-address order. Adjacent
// ranges retain overlap; holes and failed reads never join separate evidence.
func (s *linuxSocketScan) scan(layer memory.MemoryLayer, needles map[uint64]linuxSocketNeedle, maximum uint64, visit func(uint64, uint64) error) error {
	width := s.e.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return fmt.Errorf("invalid socket pointer width")
	}
	ranges := layer.Ranges()
	if len(ranges) == 0 {
		return fmt.Errorf("physical socket scan requires enumerated ranges")
	}
	buf := make([]byte, (1<<20)+width-1)
	tail := 0
	var previous uint64
	for i, r := range ranges {
		end, err := memory.Add(r.Start, r.Length)
		if err != nil || r.Length == 0 || i > 0 && r.Start < previous {
			return fmt.Errorf("invalid socket scan ranges")
		}
		if i == 0 || r.Start != previous {
			tail = 0
		}
		for pos := r.Start; pos < end; {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			want := int(min(uint64(1<<20), end-pos))
			if uint64(want) > maximum-s.scanned {
				return fmt.Errorf("socket scan byte limit exhausted")
			}
			got, cause := layer.ReadAt(s.ctx, buf[tail:tail+want], pos)
			if got < 0 || got > want {
				got = 0
				cause = fmt.Errorf("invalid physical socket scan read count")
			}
			if cause == nil && got != want {
				cause = io.ErrUnexpectedEOF
			}
			s.scanned += uint64(got)
			r := s.row(pos, "socket_scan_read")
			digest := sha256.Sum256(buf[tail : tail+got])
			r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(got)), "SHA256": evidence.Text(fmt.Sprintf("%x", digest)), "ReadComplete": evidence.Bool(cause == nil)}}
			if cause != nil {
				r.Cells["Error"] = evidence.Missing("scan_read_failed", cause)
			}
			if err := s.emit(r); err != nil {
				return err
			}
			window := buf[:tail+got]
			base := pos - uint64(tail)
			for at := 0; at+width <= len(window); at++ {
				if at&4095 == 0 {
					if err := s.ctx.Err(); err != nil {
						return err
					}
				}
				if at+width <= tail {
					continue
				}
				var value uint64
				if width == 4 {
					value = uint64(binary.LittleEndian.Uint32(window[at:]))
				} else {
					value = binary.LittleEndian.Uint64(window[at:])
				}
				if _, ok := needles[value]; ok {
					if err := visit(base+uint64(at), value); err != nil {
						return err
					}
				}
			}
			if cause != nil {
				return cause
			}
			tail = min(width-1, len(window))
			copy(buf, window[len(window)-tail:])
			pos += uint64(got)
		}
		previous = end
	}
	return s.ctx.Err()
}
