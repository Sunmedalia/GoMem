#!/usr/bin/env python3
"""Execute locked printk implementations over typed, byte-backed kernel rings."""
import argparse
import json
import itertools
from pathlib import Path
import struct
import sys
import tempfile
from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-kmsg-oracle.json"


def fixture(width, layout, scenario):
    base = lambda name: dict(kind="base", name=name)
    obj = lambda name: dict(kind="struct", name=name)
    ptr = lambda name: dict(kind="pointer", subtype=obj(name))
    field = lambda offset, typ: dict(offset=offset, type=typ)
    array = lambda count: dict(kind="array", count=count, subtype=base("u8"))
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    types, symbols = {}, {}
    data = bytearray(0x20000)
    def put(at, n, size=width):
        data[at:at+size] = n.to_bytes(size, "little")
    def symbol(name, at, typ, value, size=width):
        symbols[name] = dict(address=at, type=typ)
        put(at, value, size)
    text = b"alpha]\nbeta"
    dictionary = b"KEY=value\0OTHER=x\0"
    facility, level, caller = 1, 6, 7
    if scenario == "multiline":
        text = "one\r\n\nthree\vfour\fend\x1cnext\x85last\u2028final\u2029".encode()
    elif scenario == "invalid":
        text = b"first\xffinvalid\nlast"
    elif scenario == "caller":
        caller = 0x80000005
    elif scenario == "unknown":
        facility, level = 22, 12
    elif scenario == "empty":
        text, dictionary = b"", b""
    elif scenario == "unicode":
        text = "中文 日本語 🧠".encode()
        dictionary = b"SUB=\xffbad\0"
    if layout == "text":
        line = b"<6>[ 17.110365] alpha]\n<13>[ 2.000001] beta\n"
        if scenario == "empty":
            line = b""
        elif scenario == "multiline":
            line = "<6>[ 1.0] one\r\n<6>[\u20031.1]\u2003two\v<6>[ 1.2] end\x85".encode()
        elif scenario == "invalid":
            line = b"<6>[ 1.0] first\xffbad\n<6>[ 2.0] last\n"
        elif scenario == "unknown":
            line = b"<9999999999999999999999999999999999999>[ 1.0] large\n"
        elif scenario == "unicode":
            line = "<١٣>[ ١٢.٣٤] 中文\n<6>[ 1.0] 🧠\n".encode()
        elif scenario == "caller":
            line = b"remnant\n<6>[ 0.000000] no caller\n"
        end = len(line)
        if scenario == "wrap":
            line = b"x" * (512-len(line)) + line
            end = 512+16
        data[0x11000:0x11000+len(line)] = line
        symbol("log_buf", 0x10000, ptr("u8"), 0x11000)
        symbol("log_buf_len", 0x10008, base("u32"), 512, 4)
        symbol("log_end", 0x10010, base("u32"), end, 4)
    elif layout in ("log", "printk_log"):
        fields = dict(ts_nsec=field(0, base("u64")), len=field(8, base("u16")), text_len=field(10, base("u16")), dict_len=field(12, base("u16")), facility=field(14, base("u8")), level=field(15, base("u8")))
        if scenario == "caller":
            fields["level"] = field(15, dict(kind="bitfield", bit_position=5, bit_length=3, type=base("u8")))
        if layout == "printk_log":
            fields["caller_id"] = field(16, base("u32"))
        types[layout] = record(24, fields)
        symbol("log_buf", 0x10000, ptr(layout), 0x11000)
        symbol("log_buf_len", 0x10008, base("u32"), 512, 4)
        start = 400 if scenario == "wrap" else 0
        total = 24+len(text)+len(dictionary)
        symbol("log_first_idx", 0x10010, base("u32"), start, 4)
        symbol("log_next_idx", 0x10018, base("u32"), total, 4)
        def message(at):
            put(at, 17110365556, 8)
            put(at+8, total, 2)
            put(at+10, len(text), 2)
            put(at+12, len(dictionary), 2)
            put(at+14, facility, 1)
            put(at+15, (level << 5) | 31 if scenario == "caller" else level, 1)
            if layout == "printk_log":
                put(at+16, caller, 4)
            data[at+24:at+24+len(text)] = text
            data[at+24+len(text):at+total] = dictionary
        message(0x11000)
        if start:
            # Tail has a zero-length wrap marker, then the real record at zero.
            put(0x11000+start+8, 0, 2)
        if scenario == "empty":
            put(0x10018, 0, 4)  # first == next visits a zero wrap marker once
            put(0x11008, 0, 2)
    else:
        types["atomic_long_t"] = record(width, dict(counter=field(0, base("ulong"))))
        types["prb_data_blk_lpos"] = record(2*width, dict(begin=field(0, base("ulong")), next=field(width, base("ulong"))))
        types["prb_desc"] = record(3*width, dict(state_var=field(0, obj("atomic_long_t")), text_blk_lpos=field(width, obj("prb_data_blk_lpos"))))
        types["dev_printk_info"] = record(48, dict(subsystem=field(0, array(16)), device=field(16, array(32))))
        fields = dict(ts_nsec=field(0, base("u64")), text_len=field(8, base("u16")), facility=field(10, base("u8")), level=field(11, base("u8")), caller_id=field(12, base("u32")), dev_info=field(16, obj("dev_printk_info")))
        if scenario == "caller":
            fields["level"] = field(11, dict(kind="bitfield", bit_position=5, bit_length=3, type=base("u8")))
        types["printk_info"] = record(64, fields)
        types["prb_desc_ring"] = record(64, dict(count_bits=field(0, base("u32")), descs=field(8, ptr("prb_desc")), infos=field(16, ptr("printk_info")), head_id=field(24, obj("atomic_long_t")), tail_id=field(32, obj("atomic_long_t"))))
        types["prb_data_ring"] = record(32, dict(size_bits=field(0, base("u32")), data=field(8, ptr("u8"))))
        types["printk_ringbuffer"] = record(96, dict(desc_ring=field(0, obj("prb_desc_ring")), text_data_ring=field(64, obj("prb_data_ring"))))
        symbol("prb", 0x10000, ptr("printk_ringbuffer"), 0x11000)
        put(0x11000, 2, 4)
        put(0x11008, 0x12000)
        put(0x11010, 0x13000)
        put(0x11018, 3)
        put(0x11020, 0)
        put(0x11040, 9, 4)
        put(0x11048, 0x14000)
        for index in range(3):
            desc, info = 0x12000+index*3*width, 0x13000+index*64
            state = (1 if index == 0 else 2) << (width*8-2)
            if index == 1:
                state = 3 << (width*8-2)  # reusable descriptors produce no log
            if scenario == "empty":
                state = 0
            put(desc, state | index)
            begin, end = index*128, index*128+width+len(text)
            if scenario == "wrap" and index == 2:
                begin, end = 500, width+len(text)
            elif scenario == "caller" and index == 2:
                begin = 1  # no text; device dictionary is still emitted
            put(desc+width, begin)
            put(desc+2*width, end)
            put(info, 17110365556+index, 8)
            put(info+8, len(text), 2)
            put(info+10, facility, 1)
            put(info+11, (level << 5) | 31 if scenario == "caller" else level, 1)
            put(info+12, caller, 4)
            if scenario != "empty":
                subsystem = b"usb\xffbad" if scenario == "invalid" else b"usb"
                data[info+16:info+16+len(subsystem)] = subsystem
                data[info+32:info+32+4] = b"1-2\0"
            actual = 0 if begin > end else begin
            if begin & 1 == 0:
                data[0x14000+actual+width:0x14000+actual+width+len(text)] = text
    isf = dict(metadata={"format":"6.2.0"}, base_types={name:dict(kind="int",size=size,endian="little",signed=False) for name,size in (("pointer",width),("ulong",width),("u64",8),("u32",4),("u16",2),("u8",1))}, user_types=types, enums={}, symbols=symbols)
    # Base pointee references must be base rather than struct.
    for symbol_ in symbols.values():
        subtype = symbol_["type"].get("subtype", {})
        if subtype.get("name") == "u8":
            subtype["kind"] = "base"
    if "prb_data_ring" in types:
        types["prb_data_ring"]["fields"]["data"]["type"]["subtype"]["kind"] = "base"
    return isf, bytes(data)


def generate(source):
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires pinned source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.plugins.linux.kmsg import ABCKmsg
    cases = []
    for width in (4, 8):
        for layout in ("text", "log", "printk_log", "modern"):
            for scenario in ("normal", "empty", "wrap", "multiline", "invalid", "caller", "unknown", "unicode"):
                isf, data = fixture(width, layout, scenario)
                context = contexts.Context()
                class KernelBuffer(BufferDataLayer):
                    @property
                    def address_mask(self):
                        return (1 << (width*8))-1
                context.layers.add_layer(KernelBuffer(context,"test","memory",data))
                with tempfile.TemporaryDirectory(prefix="gomem-kmsg-oracle-") as directory:
                    path = Path(directory)/"kernel.json"
                    path.write_text(json.dumps(isf))
                    context.symbol_space.append(IntermediateSymbolTable(context,"symbols","kernel",path.as_uri()))
                    context.module("kernel","memory",0)
                    expected = [dict(facility=f,level=l,timestamp=t,caller=c,line=s) for f,l,t,c,s in ABCKmsg.run_all(context,{"kernel":"kernel"})]
                writes = []
                cursor = 0x10000
                while cursor < len(data):
                    if not data[cursor]:
                        cursor += 1
                        continue
                    start = cursor
                    while cursor < len(data) and data[cursor]:
                        cursor += 1
                    writes.append([start, data[start:cursor].hex()])
                cases.append(dict(width=width,layout=layout,scenario=scenario,isf=isf,writes=writes,expected=expected))
    controls = []
    for width in (4, 8):
        for scenario in ("id-wrap", "equal-head-tail"):
            isf, raw = fixture(width, "modern", "normal")
            data = bytearray(raw)
            head, tail = (1, (1 << (width*8-2))-2) if scenario == "id-wrap" else (0, 0)
            data[0x11018:0x11018+width] = head.to_bytes(width, "little")
            data[0x11020:0x11020+width] = tail.to_bytes(width, "little")
            context = contexts.Context()
            class ControlBuffer(BufferDataLayer):
                @property
                def address_mask(self):
                    return (1 << (width*8))-1
            context.layers.add_layer(ControlBuffer(context,"test","memory",bytes(data)))
            with tempfile.TemporaryDirectory(prefix="gomem-kmsg-control-") as directory:
                path = Path(directory)/"kernel.json"
                path.write_text(json.dumps(isf))
                context.symbol_space.append(IntermediateSymbolTable(context,"symbols","kernel",path.as_uri()))
                context.module("kernel","memory",0)
                rows = ABCKmsg.run_all(context,{"kernel":"kernel"})
                if scenario == "equal-head-tail":
                    rows = itertools.islice(rows, 16)
                expected = [dict(facility=f,level=l,timestamp=t,caller=c,line=s) for f,l,t,c,s in rows]
            writes = [[0x10000, bytes(data[0x10000:0x15000]).hex()]]
            controls.append(dict(width=width,layout="modern",scenario=scenario,isf=isf,writes=writes,expected=expected,failed=scenario=="equal-head-tail"))
    return json.dumps(dict(commit=COMMIT,scope="Unmodified ABCKmsg dispatch and all four real ISF-backed ring implementations; no reader/field method mocks",cases=cases,controls=controls),indent=2)+"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ROOT/(".cache/volatility3-"+COMMIT))
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("kmsg oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} byte-backed kmsg cases and four ID controls verified")


if __name__ == "__main__":
    main()
