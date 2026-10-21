# Explicit object data and native pointer layers

`pkg/object.View` provides typed aggregate access for objects whose bytes and
pointer targets belong to different address spaces. This is required by physical
socket scanning: a recovered `sock` or `file` can reside in physical memory while
its pointers still contain kernel virtual addresses.

`NewView(data, native, symbols, address, type)` records both layers explicitly.
`Uint`, `Int`, `Enum`, `String`, and `Bytes` read the current object's data layer.
`Embedded`, `Cast`, and `Container` retain both layers. `Dereference` reads a
pointer from the current data layer and constructs its declared struct/union
pointee in the native layer; subsequent pointer hops stay in that layer.
Numerical address ranges never select a layer. Reads do not fall back to another
layer after a fault.

For example, a physical file can be followed without treating its offset as a
kernel address:

```go
file, err := object.NewView(physical, kernel, table, fileOffset, "file")
// Check each error before continuing.
dentry, err := file.Dereference(ctx, "f_path.dentry")
inode, err := dentry.Dereference(ctx, "d_inode")
allocation, err := inode.Container("socket_alloc", "vfs_inode")
socket, err := allocation.Embedded("socket")
sock, err := socket.Dereference(ctx, "sk")
```

Construction validates aggregate types and address arithmetic without requiring
all object bytes to be resident. Casts preserve the exact address, while
containers subtract the declared member offset after checking its type. Accessors
preserve the existing reader's bounds, signedness, enum and pointer-width rules.
Null pointer targets return `object.ErrNullPointer`, including when address zero
is mapped. Other read failures remain errors. A missing native layer permits
local access but prevents pointer dereferencing.

This API does not prove that recovered memory represents a live object. It does
not translate pointer values, canonicalize addresses, infer void-pointer target
types, walk pointer arrays, acquire an entire structure automatically, or provide
an acquisition log. Callers must choose layers, record raw reads and provenance,
and apply plugin-specific validity and resource bounds. `Bytes` returns an error
on a partial read; evidence collectors that need the captured prefix should use
the exposed `Layer` with their acquisition wrapper.

## Validation

`tools/build_object_view_oracle.py` executes unmodified fixed-baseline Volatility
objects and `LinuxUtilities.container_of`, using separate byte-backed physical
and native layers. Their address masks preserve the declared architecture width.
The same numerical addresses intentionally contain different bytes in the two
layers. Sixteen cases cover 32/64-bit pointers, both endian orders, nulls,
unmapped pointer targets and truncated pointer storage. Each case records ten
operations, including embedded/cast reads, two pointer hops and the physical
file-to-native-socket chain. The null-target policy is explicitly applied to the
reference transcript; it is a GoMem policy rather than an upstream read failure.

`TestViewPinnedDataAndNativeLayers` compares all 160 recorded operations.
Additional tests exercise invalid transitions, absent native layers, address
arithmetic, short reads without errors, cancellation, and a declared 32-bit
pointer inside a 64-bit symbol table. `FuzzViewDataAndNativeLayers` mutates
pointer storage and addresses, then independently checks successful target reads
against the native reader. CI regenerates the reference fixture and runs fuzzing.

This is shared object infrastructure. It does not change the capability count or
mark `linux.sockscan` implemented; scanner sources, deduplication, endpoint
extraction and the saved real-image reference still need integration.
