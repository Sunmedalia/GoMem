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
	"sort"
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
func loadLibrary(path string) (*C.gomem_yara_library, error) {
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
	return library, nil
}
func compileNative(path string, config CompileConfig) (nativeRules, error) {
	library, err := loadLibrary(path)
	if err != nil {
		return nil, err
	}
	var allocated []unsafe.Pointer
	defer func() {
		for _, p := range allocated {
			C.free(p)
		}
	}()
	cString := func(value string) *C.char {
		p := C.CString(value)
		allocated = append(allocated, unsafe.Pointer(p))
		return p
	}
	sourceMemory := C.calloc(C.size_t(len(config.Sources)), C.size_t(C.sizeof_gomem_yara_source))
	if sourceMemory == nil {
		return nil, fmt.Errorf("YARA-X source allocation failed")
	}
	defer C.free(sourceMemory)
	sources := unsafe.Slice((*C.gomem_yara_source)(sourceMemory), len(config.Sources))
	for n, source := range config.Sources {
		namespace := source.Namespace
		if namespace == "" {
			namespace = "default"
		}
		sources[n].namespace_name = cString(namespace)
		sources[n].text = cString(string(source.Text))
	}
	var globals *C.gomem_yara_global
	if len(config.Globals) != 0 {
		p := C.calloc(C.size_t(len(config.Globals)), C.size_t(C.sizeof_gomem_yara_global))
		if p == nil {
			return nil, fmt.Errorf("YARA-X external allocation failed")
		}
		defer C.free(p)
		globals = (*C.gomem_yara_global)(p)
		values := unsafe.Slice(globals, len(config.Globals))
		names := make([]string, 0, len(config.Globals))
		for name := range config.Globals {
			names = append(names, name)
		}
		sort.Strings(names)
		for n, name := range names {
			values[n].name = cString(name)
			values[n].json = cString(string(config.Globals[name]))
		}
	}
	var diagnostic *C.char
	var warnings *C.char
	rules := C.gomem_yara_compile(library, (*C.gomem_yara_source)(sourceMemory), C.size_t(len(sources)), globals, C.size_t(len(config.Globals)), &diagnostic, &warnings)
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
func deserializeNative(path string, data []byte) (nativeRules, error) {
	library, err := loadLibrary(path)
	if err != nil {
		return nil, err
	}
	rules := C.gomem_yara_deserialize(library, unsafe.Pointer(&data[0]), C.size_t(len(data)))
	if rules == nil {
		return nil, fmt.Errorf("YARA-X compiled rules are invalid or incompatible")
	}
	return &yaraNative{rules: rules}, nil
}
func (n *yaraNative) Serialize() ([]byte, error) {
	var p unsafe.Pointer
	var length C.size_t
	code := C.gomem_yara_serialize(n.rules, &p, &length)
	if p != nil {
		defer C.free(p)
	}
	if code != 0 {
		return nil, fmt.Errorf("YARA-X serialization failed or exceeds %d bytes", MaxCompiled)
	}
	return C.GoBytes(p, C.int(length)), nil
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
