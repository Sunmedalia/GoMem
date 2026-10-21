package plugins

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Keep the pinned handler insertion order. Aliased addresses take the last
// declared scalar type; boolean rendering still uses the special getter map.
var linuxParamIntegers = []struct{ getter, typ string }{
	{"param_get_invbool", "int"}, {"param_get_bool", "int"}, {"param_get_int", "int"},
	{"param_get_ulong", "long unsigned int"}, {"param_get_ullong", "long long unsigned int"},
	{"param_get_long", "long int"}, {"param_get_uint", "unsigned int"},
	{"param_get_ushort", "short unsigned int"}, {"param_get_short", "short int"}, {"param_get_byte", "char"},
}

type linuxParamDecoder struct {
	n                   *linuxModuleRead
	integers            map[uint64]string
	getters             map[string]uint64
	active              map[uint64]bool
	visits, stringBytes int
}

func newLinuxParamDecoder(n *linuxModuleRead) *linuxParamDecoder {
	d := &linuxParamDecoder{n: n, integers: map[uint64]string{}, getters: map[string]uint64{}, active: map[uint64]bool{}}
	for _, h := range linuxParamIntegers {
		if at, err := n.e.Symbol(h.getter); err == nil {
			d.integers[at] = h.typ
		}
	}
	for _, name := range []string{"param_array_get", "param_get_string", "param_get_charp", "param_get_bool", "param_get_invbool"} {
		if at, err := n.e.Symbol(name); err == nil {
			d.getters[name] = at
		}
	}
	return d
}

func linuxModuleArguments(n *linuxModuleRead, module uint64) (string, error) {
	present, err := n.has("module", "kp")
	if err != nil {
		return "", err
	}
	if !present {
		n.fields["module_parameters"] = evidence.Missing("parameter_table_not_in_layout", nil)
		return "", nil
	}
	count, err := n.uint(module, "module", "num_kp")
	if err != nil {
		return "", err
	}
	if count > 128 {
		return "", fmt.Errorf("module parameter count %d exceeds 128", count)
	}
	if count == 0 {
		return "", nil
	}
	kp, err := n.uint(module, "module", "kp")
	if err != nil {
		return "", err
	}
	if kp == 0 {
		return "", fmt.Errorf("nonempty module parameter table has null kp")
	}
	param, err := n.e.Symbols.Type("kernel_param")
	if err != nil || param.Size == 0 || param.Size > 4096 {
		return "", fmt.Errorf("kernel_param stride unavailable or exceeds 4096: %v", err)
	}
	if param.Size > (^uint64(0)-kp)/(count) {
		return "", fmt.Errorf("kernel parameter address overflow")
	}
	d := newLinuxParamDecoder(n)
	var parts []string
	var failures pluginFailures
	for i := uint64(0); i < count; i++ {
		if err := n.ctx.Err(); err != nil {
			return strings.Join(parts, ", "), err
		}
		at := kp + i*param.Size
		namePtr, err := n.uint(at, "kernel_param", "name")
		if err != nil {
			failures.add(err)
			continue
		}
		name, err := d.text(namePtr, 32, fmt.Sprintf("param_name@%x", at))
		if err != nil {
			failures.add(err)
			continue
		}
		value, err := d.value(at, 0)
		if err != nil {
			failures.add(err)
			continue
		}
		parts = append(parts, name+"="+linuxParamDisplay(value))
	}
	return strings.Join(parts, ", "), failures.err("module load parameters")
}

func linuxParamDisplay(v evidence.Value) string {
	if v.Kind == "missing" {
		return "None"
	}
	return v.String()
}

func (d *linuxParamDecoder) text(address uint64, count uint64, key string) (string, error) {
	if count == 0 || count > 4096 {
		return "", fmt.Errorf("module parameter string extent %d outside 1..4096", count)
	}
	if count > uint64((1<<20)-d.stringBytes) {
		return "", fmt.Errorf("module parameter strings exceed 1048576 bytes")
	}
	d.stringBytes += int(count)
	raw, proof, err := linuxCaptureRange(d.n.ctx, d.n.e.Kernel, address, int(count))
	d.n.fields[key] = proof
	if err != nil {
		return "", err
	}
	return spoofDecoded(raw), nil
}

func (d *linuxParamDecoder) value(param uint64, depth int) (value evidence.Value, err error) {
	// Every outcome, including an unknown getter or partial read, is structured
	// evidence. The legacy display alone cannot distinguish None from an error.
	defer func() {
		if err != nil {
			value = evidence.Missing("parameter_decode_incomplete", err)
		}
		d.n.fields[fmt.Sprintf("param_value@%x", param)] = value
	}()
	if err = d.n.ctx.Err(); err != nil {
		return value, err
	}
	if depth >= 16 || d.visits >= 4096 || d.active[param] {
		return value, fmt.Errorf("kernel parameter recursion, cycle or visit bound exceeded at %#x", param)
	}
	d.visits++
	d.active[param] = true
	defer delete(d.active, param)
	getter, err := linuxParamGetter(d.n, param)
	if err != nil {
		return value, err
	}
	if getter == 0 {
		return evidence.Missing("parameter_getter_null", nil), nil
	}
	if getter == d.getters["param_array_get"] {
		return d.array(param, depth)
	}
	if getter == d.getters["param_get_string"] || getter == d.getters["param_get_charp"] {
		ptr, err := d.n.uint(param, "kernel_param", "str")
		if err != nil {
			return value, err
		}
		count := uint64(256)
		if getter == d.getters["param_get_string"] {
			_, typ, err := linuxParamContainer(d.n, param, "str", "kparam_string")
			if err != nil {
				return value, err
			}
			count, err = d.n.uint(ptr, typ, "maxlen")
			if err != nil {
				return value, err
			}
		}
		// The fixed baseline reads from param.str itself, including for kparam_string.
		// Preserve that address choice rather than silently chasing a nested string.
		text, err := d.text(ptr, count, fmt.Sprintf("param_string@%x", param))
		return evidence.Text(text), err
	}
	if typ, ok := d.integers[getter]; ok {
		arg, err := d.n.uint(param, "kernel_param", "arg")
		if err != nil {
			return value, err
		}
		ref := symbols.TypeRef{Kind: "base", Name: typ}
		base, err := d.n.e.Objects.ScalarType(ref)
		if err != nil {
			return value, err
		}
		if base.SignedUnknown {
			return value, fmt.Errorf("parameter scalar %s has unknown signedness", typ)
		}
		raw, err := d.n.scalar(arg, ref)
		if err != nil {
			return value, err
		}
		if getter == d.getters["param_get_bool"] || getter == d.getters["param_get_invbool"] {
			yes := raw != 0
			if getter == d.getters["param_get_invbool"] {
				yes = !yes
			}
			if yes {
				return evidence.Text("Y"), nil
			}
			return evidence.Text("N"), nil
		}
		if base.Signed {
			width, err := d.n.e.Objects.Size(ref)
			if err != nil || width < 1 || width > 8 {
				return value, fmt.Errorf("invalid signed parameter extent %d: %v", width, err)
			}
			shift := 64 - width*8
			return evidence.Integer(int64(raw<<shift) >> shift), nil
		}
		return evidence.Number(raw), nil
	}
	return evidence.Missing("parameter_getter_unknown", nil), nil
}

func (d *linuxParamDecoder) array(param uint64, depth int) (evidence.Value, error) {
	at, typ, err := linuxParamContainer(d.n, param, "arr", "kparam_array")
	if err != nil {
		return evidence.Value{}, err
	}
	num, err := d.n.uint(at, typ, "num")
	if err != nil {
		return evidence.Value{}, err
	}
	var count uint64
	if num != 0 {
		field, err := d.n.e.Objects.Field(typ, "num")
		if err != nil {
			return evidence.Value{}, err
		}
		if field.Type.Kind != "pointer" || field.Type.Underlying() == nil {
			return evidence.Value{}, fmt.Errorf("array num requires a typed scalar pointer")
		}
		count, err = d.n.scalar(num, *field.Type.Underlying())
		if err != nil {
			return evidence.Value{}, err
		}
	} else {
		count, err = d.n.uint(at, typ, "max")
		if err != nil {
			return evidence.Value{}, err
		}
	}
	if count > 32 {
		return evidence.Value{}, fmt.Errorf("parameter array count %d exceeds 32", count)
	}
	if count == 0 {
		return evidence.Missing("parameter_array_empty", nil), nil
	}
	step, err := d.n.uint(at, typ, "elemsize")
	if err != nil {
		return evidence.Value{}, err
	}
	elem, err := d.n.uint(at, typ, "elem")
	if err != nil {
		return evidence.Value{}, err
	}
	if elem == 0 || step == 0 && count > 1 || step > (^uint64(0)-elem)/count {
		return evidence.Value{}, fmt.Errorf("invalid parameter array element extent")
	}
	fields := map[string]evidence.Value{}
	d.n.fields[fmt.Sprintf("param_elements@%x", param)] = evidence.Value{Kind: "structure", Data: fields}
	var parts []string
	for i := uint64(0); i < count; i++ {
		value, err := d.value(elem+i*step, depth+1)
		fields[strconv.FormatUint(i, 10)] = value
		if err != nil {
			return evidence.Value{}, err
		}
		parts = append(parts, linuxParamDisplay(value))
	}
	return evidence.Text(strings.Join(parts, ",")), nil
}

// ObjectReader field paths describe inline members; a pointer to ops must be
// dereferenced explicitly before reading its get member.
func linuxParamGetter(n *linuxModuleRead, param uint64) (uint64, error) {
	if ok, err := n.has("kernel_param", "get"); err != nil {
		return 0, err
	} else if ok {
		return n.uint(param, "kernel_param", "get")
	}
	at, typ, err := linuxParamContainer(n, param, "ops", "kernel_param_ops")
	if err != nil {
		return 0, err
	}
	return n.uint(at, typ, "get")
}

func linuxParamContainer(n *linuxModuleRead, param uint64, field, fallback string) (uint64, string, error) {
	f, err := n.e.Objects.Field("kernel_param", field)
	if err != nil {
		return 0, "", err
	}
	typ := fallback
	if f.Type.Kind == "struct" || f.Type.Kind == "union" {
		at, err := memory.Add(param, f.Offset)
		return at, f.Type.Name, err
	}
	if f.Type.Kind != "pointer" {
		return 0, "", fmt.Errorf("kernel_param.%s is not a structure or pointer", field)
	}
	if sub := f.Type.Underlying(); sub != nil {
		if sub.Kind != "struct" && sub.Kind != "union" {
			return 0, "", fmt.Errorf("kernel_param.%s does not point to a structure", field)
		}
		typ = sub.Name
	}
	at, err := n.uint(param, "kernel_param", field)
	if err != nil {
		return 0, "", err
	}
	if at == 0 {
		return 0, "", fmt.Errorf("kernel_param.%s is null", field)
	}
	return at, typ, nil
}
