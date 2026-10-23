//go:build cgo && (linux || darwin || windows)

package memory

/*
#cgo linux LDFLAGS: -ldl
#include <stdint.h>
#include <stdlib.h>
typedef struct gomem_lc gomem_lc;
gomem_lc *gomem_lc_open(const char *, const char *, const char *);
void gomem_lc_close(gomem_lc *);
int gomem_lc_map(gomem_lc *, uint64_t **, uint32_t *);
int gomem_lc_read(gomem_lc *, uint64_t, uint32_t, void *);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type nativeLeechCore struct{ handle *C.gomem_lc }

func LeechCoreSupported() bool { return true }
func openNativeLeechCore(library, device, remote string) (leechCoreDevice, error) {
	l, d, r := C.CString(library), C.CString(device), C.CString(remote)
	defer C.free(unsafe.Pointer(l))
	defer C.free(unsafe.Pointer(d))
	defer C.free(unsafe.Pointer(r))
	h := C.gomem_lc_open(l, d, r)
	if h == nil {
		return nil, fmt.Errorf("LeechCore library loading or device opening failed")
	}
	return &nativeLeechCore{h}, nil
}
func (n *nativeLeechCore) Close() {
	if n.handle != nil {
		C.gomem_lc_close(n.handle)
		n.handle = nil
	}
}
func (n *nativeLeechCore) Ranges() ([]Range, error) {
	var data *C.uint64_t
	var count C.uint32_t
	if C.gomem_lc_map(n.handle, &data, &count) == 0 {
		return nil, fmt.Errorf("LeechCore memory map unavailable or invalid")
	}
	defer C.free(unsafe.Pointer(data))
	fields := unsafe.Slice(data, int(count)*3)
	ranges := make([]Range, int(count))
	for i := range ranges {
		ranges[i] = Range{Start: uint64(fields[i*3]), Length: uint64(fields[i*3+1])}
	}
	return ranges, nil
}
func (n *nativeLeechCore) Read(p []byte, at uint64) bool {
	if len(p) == 0 {
		return true
	}
	if len(p) > MaxRead {
		return false
	}
	return C.gomem_lc_read(n.handle, C.uint64_t(at), C.uint32_t(len(p)), unsafe.Pointer(&p[0])) != 0
}
