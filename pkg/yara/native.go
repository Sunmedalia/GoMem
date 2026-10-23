//go:build cgo && (windows || linux || darwin)

package yara

/*
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include "bridge.h"
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"
)

var libraries = struct {
	sync.Mutex
	values map[string]*C.gomem_yara_library
}{values: make(map[string]*C.gomem_yara_library)}

type yaraNative struct {
	rules    *C.gomem_yara_rules
	warnings json.RawMessage
}

func Supported() bool { return true }
func compileNative(path string, source []byte) (nativeRules, error) {
	libraries.Lock()
	library := libraries.values[path]
	if library == nil {
		if len(libraries.values) >= 8 {
			libraries.Unlock()
			return nil, fmt.Errorf("YARA-X process library limit exhausted")
		}
		name := C.CString(path)
		library = C.gomem_yara_load(name)
		C.free(unsafe.Pointer(name))
		if library != nil {
			libraries.values[path] = library
		}
	}
	libraries.Unlock()
	if library == nil {
		return nil, fmt.Errorf("YARA-X library loading or required C API symbols unavailable")
	}
	text := C.CString(string(source))
	defer C.free(unsafe.Pointer(text))
	var diagnostic *C.char
	var warnings *C.char
	rules := C.gomem_yara_compile(library, text, &diagnostic, &warnings)
	if warnings != nil {
		defer C.free(unsafe.Pointer(warnings))
	}
	if diagnostic != nil {
		defer C.free(unsafe.Pointer(diagnostic))
	}
	if rules == nil {
		var raw json.RawMessage
		if diagnostic != nil {
			value := []byte(C.GoString(diagnostic))
			if json.Valid(value) {
				raw = value
			}
		}
		return nil, &CompileError{Diagnostics: raw}
	}
	var rawWarnings json.RawMessage
	if warnings != nil {
		rawWarnings = []byte(C.GoString(warnings))
		if !json.Valid(rawWarnings) {
			C.gomem_yara_rules_free(rules)
			return nil, fmt.Errorf("invalid native YARA-X warning diagnostics")
		}
	}
	return &yaraNative{rules: rules, warnings: rawWarnings}, nil
}
func (n *yaraNative) Warnings() json.RawMessage { return n.warnings }
func (n *yaraNative) Close() {
	if n.rules != nil {
		C.gomem_yara_rules_free(n.rules)
		n.rules = nil
	}
}
func (n *yaraNative) Scan(data []byte, options Options) ([]Match, error) {
	var p unsafe.Pointer
	if len(data) != 0 {
		p = unsafe.Pointer(&data[0])
	}
	result := C.gomem_yara_result{limit: C.uint32_t(options.MaxMatches), budget: C.uint64_t(options.MaxOutputBytes)}
	defer C.gomem_yara_result_free(&result)
	code := C.gomem_yara_scan(n.rules, p, C.size_t(len(data)), C.uint64_t(options.TimeoutSeconds), &result)
	if code == 4 {
		return nil, ErrTimeout
	}
	if code != 0 {
		return nil, fmt.Errorf("YARA-X native scan failed (code %d)", int(code))
	}
	if result.error == 1 {
		return nil, ErrLimit
	}
	if result.error != 0 {
		return nil, fmt.Errorf("YARA-X native result collection failed")
	}
	items := unsafe.Slice(result.matches, int(result.count))
	matches := make([]Match, 0, len(items))
	for _, m := range items {
		matches = append(matches, Match{Namespace: C.GoString(m.namespace_name), Rule: C.GoString(m.rule), Pattern: C.GoString(m.pattern), Offset: uint64(m.offset), Length: uint64(m.length), RuleOnly: m.rule_only != 0})
	}
	return matches, nil
}
