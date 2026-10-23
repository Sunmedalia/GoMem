//go:build cgo && (linux || darwin || windows)

package disasm

/*
#cgo linux LDFLAGS: -ldl
#include <stdint.h>
#include <stdlib.h>
typedef struct gomem_cs gomem_cs;
typedef struct {uint64_t address;uint16_t size;uint8_t bytes[24];char mnemonic[32];char operands[160];} gomem_instruction;
gomem_cs *gomem_cs_open(const char *,int);
void gomem_cs_close(gomem_cs *);
int gomem_cs_reset(gomem_cs *);
int gomem_cs_next(gomem_cs *,const void *,size_t,uint64_t,gomem_instruction *);
unsigned gomem_cs_minor(gomem_cs *);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type capstoneNative struct {
	handle  *C.gomem_cs
	version string
}

func Supported() bool { return true }
func openNative(library, arch string) (nativeDecoder, error) {
	modes := map[string]int{"x86": 0, "x64": 1, "arm": 2, "arm64": 3, "thumb": 4}
	path := C.CString(library)
	defer C.free(unsafe.Pointer(path))
	handle := C.gomem_cs_open(path, C.int(modes[arch]))
	if handle == nil {
		return nil, fmt.Errorf("Capstone v5 library loading or decoder initialization failed")
	}
	return &capstoneNative{handle: handle, version: fmt.Sprintf("5.%d", uint(C.gomem_cs_minor(handle)))}, nil
}
func (n *capstoneNative) Version() string { return n.version }
func (n *capstoneNative) Reset() error {
	if C.gomem_cs_reset(n.handle) == 0 {
		return fmt.Errorf("Capstone stream initialization failed")
	}
	return nil
}
func (n *capstoneNative) Close() {
	if n.handle != nil {
		C.gomem_cs_close(n.handle)
		n.handle = nil
	}
}
func (n *capstoneNative) Next(data []byte, address uint64) (Instruction, error) {
	var out C.gomem_instruction
	if len(data) == 0 || C.gomem_cs_next(n.handle, unsafe.Pointer(&data[0]), C.size_t(len(data)), C.uint64_t(address), &out) == 0 {
		return Instruction{}, fmt.Errorf("invalid, incomplete or unsupported instruction")
	}
	size := int(out.size)
	if size == 0 || size > 24 {
		return Instruction{}, fmt.Errorf("invalid native instruction size")
	}
	return Instruction{Address: uint64(out.address), Bytes: C.GoBytes(unsafe.Pointer(&out.bytes[0]), C.int(size)), Mnemonic: C.GoString(&out.mnemonic[0]), Operands: C.GoString(&out.operands[0])}, nil
}
