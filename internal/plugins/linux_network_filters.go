package plugins

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func linuxSocketFilters(n *linuxNetReader, sock uint64) {
	filters := []map[string]string{}
	displays := []string{}
	for _, candidate := range []struct{ field, typ, kind string }{{"sk_filter", "sk_filter", "socket_filter"}, {"sk_reuseport_cb", "sock_reuseport", "reuseport_filter"}} {
		if !n.optional("sock", candidate.field) {
			continue
		}
		filter, ok := n.pointer(candidate.field+"Pointer", sock, "sock", candidate.field)
		if !ok {
			continue
		}
		if filter == 0 {
			continue
		}
		typ := candidate.typ
		// The pointed-to type is authoritative, including kernel-specific names for
		// the reuseport control block. Do not infer offsets from a type-name guess.
		field, err := n.e.Objects.Field("sock", candidate.field)
		if err != nil {
			n.fail("Filter", "filter_layout_unavailable", err)
			continue
		}
		if field.Type.Subtype != nil && field.Type.Subtype.Name != "" {
			typ = field.Type.Subtype.Name
		}
		header, err := n.e.Symbols.Type(typ)
		if err != nil || header.Size == 0 {
			n.fail("Filter", "filter_layout_unavailable", fmt.Errorf("filter header type/size unavailable: %v", err))
			continue
		}
		if _, err = n.raw(candidate.field+"HeaderRaw", filter, int(min(header.Size, 64))); err != nil {
			n.fail("Filter", "filter_header_unreadable", err)
			continue
		}
		info := map[string]string{"filter_type": candidate.kind, "bpf_filter_type": "cBPF", "address": fmt.Sprintf("0x%x", filter)}
		if n.optional(typ, "prog") {
			prog, ok := n.pointer(candidate.field+"Program", filter, typ, "prog")
			if !ok {
				continue
			}
			if prog != 0 {
				info["program_address"] = fmt.Sprintf("0x%x", prog)
				aux := uint64(0)
				if n.optional("bpf_prog", "aux") {
					var ok bool
					aux, ok = n.pointer(candidate.field+"ProgramAux", prog, "bpf_prog", "aux")
					if !ok {
						continue
					}
				}
				value, known := uint64(0), false
				if n.optional("bpf_prog", "type") {
					value, known = n.uint(candidate.field+"ProgramType", prog, "bpf_prog", "type")
				} else if aux != 0 && n.optional("bpf_prog_aux", "prog_type") {
					value, known = n.uint(candidate.field+"ProgramType", aux, "bpf_prog_aux", "prog_type")
				}
				if known {
					info["program_type"] = strconv.FormatUint(value, 10)
					if value == 1 {
						info["bpf_filter_type"] = "eBPF"
					} else if value != 0 {
						info["bpf_filter_type"] = fmt.Sprintf("UNK(%d)", value)
					}
					if value == 1 && aux != 0 {
						if n.optional("bpf_prog_aux", "id") {
							if id, ok := n.uint(candidate.field+"ProgramID", aux, "bpf_prog_aux", "id"); ok {
								info["bpf_filter_id"] = strconv.FormatUint(id, 10)
							}
						}
						if n.optional("bpf_prog_aux", "name") {
							nameField, er := n.e.Objects.Field("bpf_prog_aux", "name")
							size, er2 := n.e.Objects.Size(nameField.Type)
							if er != nil || er2 != nil || size > 256 {
								n.fail("Filter", "bpf_name_layout_unavailable", fmt.Errorf("invalid BPF name layout"))
								continue
							}
							if _, er = n.fieldBytes(candidate.field+"ProgramNameRaw", aux, "bpf_prog_aux", "name", int(size)); er != nil {
								n.fail("Filter", "bpf_name_unreadable", er)
								continue
							}
							name, err := n.e.Objects.String(n.ctx, aux, "bpf_prog_aux", "name", 256)
							if err != nil {
								n.fail("Filter", "bpf_name_unreadable", err)
							} else if name != "" {
								info["bpf_filter_name"] = name
							}
						}
					}
				}
			}
		}
		filters = append(filters, info)
		pieces := []string{}
		for _, key := range []string{"filter_type", "bpf_filter_type", "bpf_filter_id", "bpf_filter_name"} {
			if value, ok := info[key]; ok {
				pieces = append(pieces, key+"="+value)
			}
		}
		displays = append(displays, strings.Join(pieces, ","))
	}
	n.cells["Filters"] = evidence.Value{Kind: "structure", Data: filters}
	if len(displays) > 0 && n.cells["Filter"].Error == "" {
		n.cells["Filter"] = evidence.Text(displays[len(displays)-1])
	}
}
