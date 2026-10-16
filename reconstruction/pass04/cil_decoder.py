"""
Minimal standalone ECMA-335 CIL instruction decoder.

Used as a supplementary static-analysis tool during this engagement to recover
full, in-order instruction streams for PixelTone.exe method bodies, since REA's
`inspect-managed-members` anchors are a curated subset, not the full stream.

Reads raw method body bytes directly from the target PE file at the file_offset
reported by REA (method header already skipped by caller) and decodes opcodes
per the standard ECMA-335 opcode tables (single-byte, and 0xFE-prefixed
two-byte). This is pure static analysis: no part of the target is executed.
"""
import struct

# (mnemonic, operand_kind, operand_size) for single-byte opcodes 0x00-0xFE(prefix)/0xFF
# operand_kind: None, 'i8'(sbyte),'i32','i64','r4','r8','var8'(ubyte local/arg idx),
# 'var16'(ushort local/arg idx),'tok'(4-byte metadata token),'br8'(sbyte branch),'br32'(int branch),
# 'switch'

SINGLE = {
0x00:("nop",None,0),0x01:("break",None,0),
0x02:("ldarg.0",None,0),0x03:("ldarg.1",None,0),0x04:("ldarg.2",None,0),0x05:("ldarg.3",None,0),
0x06:("ldloc.0",None,0),0x07:("ldloc.1",None,0),0x08:("ldloc.2",None,0),0x09:("ldloc.3",None,0),
0x0A:("stloc.0",None,0),0x0B:("stloc.1",None,0),0x0C:("stloc.2",None,0),0x0D:("stloc.3",None,0),
0x0E:("ldarg.s","var8",1),0x0F:("ldarga.s","var8",1),0x10:("starg.s","var8",1),
0x11:("ldloc.s","var8",1),0x12:("ldloca.s","var8",1),0x13:("stloc.s","var8",1),
0x14:("ldnull",None,0),0x15:("ldc.i4.m1",None,0),
0x16:("ldc.i4.0",None,0),0x17:("ldc.i4.1",None,0),0x18:("ldc.i4.2",None,0),0x19:("ldc.i4.3",None,0),
0x1A:("ldc.i4.4",None,0),0x1B:("ldc.i4.5",None,0),0x1C:("ldc.i4.6",None,0),0x1D:("ldc.i4.7",None,0),
0x1E:("ldc.i4.8",None,0),0x1F:("ldc.i4.s","i8",1),0x20:("ldc.i4","i32",4),0x21:("ldc.i8","i64",8),
0x22:("ldc.r4","r4",4),0x23:("ldc.r8","r8",8),0x25:("dup",None,0),0x26:("pop",None,0),
0x27:("jmp","tok",4),0x28:("call","tok",4),0x29:("calli","tok",4),0x2A:("ret",None,0),
0x2B:("br.s","br8",1),0x2C:("brfalse.s","br8",1),0x2D:("brtrue.s","br8",1),
0x2E:("beq.s","br8",1),0x2F:("bge.s","br8",1),0x30:("bgt.s","br8",1),0x31:("ble.s","br8",1),
0x32:("blt.s","br8",1),0x33:("bne.un.s","br8",1),0x34:("bge.un.s","br8",1),0x35:("bgt.un.s","br8",1),
0x36:("ble.un.s","br8",1),0x37:("blt.un.s","br8",1),
0x38:("br","br32",4),0x39:("brfalse","br32",4),0x3A:("brtrue","br32",4),
0x3B:("beq","br32",4),0x3C:("bge","br32",4),0x3D:("bgt","br32",4),0x3E:("ble","br32",4),
0x3F:("blt","br32",4),0x40:("bne.un","br32",4),0x41:("bge.un","br32",4),0x42:("bgt.un","br32",4),
0x43:("ble.un","br32",4),0x44:("blt.un","br32",4),0x45:("switch","switch",None),
0x46:("ldind.i1",None,0),0x47:("ldind.u1",None,0),0x48:("ldind.i2",None,0),0x49:("ldind.u2",None,0),
0x4A:("ldind.i4",None,0),0x4B:("ldind.u4",None,0),0x4C:("ldind.i8",None,0),0x4D:("ldind.i",None,0),
0x4E:("ldind.r4",None,0),0x4F:("ldind.r8",None,0),0x50:("ldind.ref",None,0),0x51:("stind.ref",None,0),
0x52:("stind.i1",None,0),0x53:("stind.i2",None,0),0x54:("stind.i4",None,0),0x55:("stind.i8",None,0),
0x56:("stind.r4",None,0),0x57:("stind.r8",None,0),
0x58:("add",None,0),0x59:("sub",None,0),0x5A:("mul",None,0),0x5B:("div",None,0),0x5C:("div.un",None,0),
0x5D:("rem",None,0),0x5E:("rem.un",None,0),0x5F:("and",None,0),0x60:("or",None,0),0x61:("xor",None,0),
0x62:("shl",None,0),0x63:("shr",None,0),0x64:("shr.un",None,0),0x65:("neg",None,0),0x66:("not",None,0),
0x67:("conv.i1",None,0),0x68:("conv.i2",None,0),0x69:("conv.i4",None,0),0x6A:("conv.i8",None,0),
0x6B:("conv.r4",None,0),0x6C:("conv.r8",None,0),0x6D:("conv.u4",None,0),0x6E:("conv.u8",None,0),
0x6F:("callvirt","tok",4),0x70:("cpobj","tok",4),0x71:("ldobj","tok",4),0x72:("ldstr","tok",4),
0x73:("newobj","tok",4),0x74:("castclass","tok",4),0x75:("isinst","tok",4),
0x76:("conv.r.un",None,0),0x79:("unbox","tok",4),0x7A:("throw",None,0),
0x7B:("ldfld","tok",4),0x7C:("ldflda","tok",4),0x7D:("stfld","tok",4),
0x7E:("ldsfld","tok",4),0x7F:("ldsflda","tok",4),0x80:("stsfld","tok",4),
0x81:("stobj","tok",4),0x82:("conv.ovf.i1.un",None,0),0x83:("conv.ovf.i2.un",None,0),
0x84:("conv.ovf.i4.un",None,0),0x85:("conv.ovf.i8.un",None,0),0x86:("conv.ovf.u1.un",None,0),
0x87:("conv.ovf.u2.un",None,0),0x88:("conv.ovf.u4.un",None,0),0x89:("conv.ovf.u8.un",None,0),
0x8A:("conv.ovf.i.un",None,0),0x8B:("conv.ovf.u.un",None,0),
0x8C:("box","tok",4),0x8D:("newarr","tok",4),0x8E:("ldlen",None,0),0x8F:("ldelema","tok",4),
0x90:("ldelem.i1",None,0),0x91:("ldelem.u1",None,0),0x92:("ldelem.i2",None,0),0x93:("ldelem.u2",None,0),
0x94:("ldelem.i4",None,0),0x95:("ldelem.u4",None,0),0x96:("ldelem.i8",None,0),0x97:("ldelem.i",None,0),
0x98:("ldelem.r4",None,0),0x99:("ldelem.r8",None,0),0x9A:("ldelem.ref",None,0),
0x9B:("stelem.i",None,0),0x9C:("stelem.i1",None,0),0x9D:("stelem.i2",None,0),0x9E:("stelem.i4",None,0),
0x9F:("stelem.i8",None,0),0xA0:("stelem.r4",None,0),0xA1:("stelem.r8",None,0),0xA2:("stelem.ref",None,0),
0xA3:("ldelem","tok",4),0xA4:("stelem","tok",4),0xA5:("unbox.any","tok",4),
0xB3:("conv.ovf.i1",None,0),0xB4:("conv.ovf.u1",None,0),0xB5:("conv.ovf.i2",None,0),
0xB6:("conv.ovf.u2",None,0),0xB7:("conv.ovf.i4",None,0),0xB8:("conv.ovf.u4",None,0),
0xB9:("conv.ovf.i8",None,0),0xBA:("conv.ovf.u8",None,0),
0xC2:("refanyval","tok",4),0xC3:("ckfinite",None,0),0xC6:("mkrefany","tok",4),
0xC7:("?",None,0),0xD0:("ldtoken","tok",4),0xD1:("conv.u2",None,0),0xD2:("conv.u1",None,0),
0xD3:("conv.i",None,0),0xD4:("conv.ovf.i",None,0),0xD5:("conv.ovf.u",None,0),
0xD6:("add.ovf",None,0),0xD7:("add.ovf.un",None,0),0xD8:("mul.ovf",None,0),0xD9:("mul.ovf.un",None,0),
0xDA:("sub.ovf",None,0),0xDB:("sub.ovf.un",None,0),0xDC:("endfinally",None,0),
0xDD:("leave","br32",4),0xDE:("leave.s","br8",1),0xDF:("stind.i",None,0),0xE0:("conv.u",None,0),
}

TWOBYTE = {
0x00:("arglist",None,0),0x01:("ceq",None,0),0x02:("cgt",None,0),0x03:("cgt.un",None,0),
0x04:("clt",None,0),0x05:("clt.un",None,0),0x06:("ldftn","tok",4),0x07:("ldvirtftn","tok",4),
0x09:("ldarg","var16",2),0x0A:("ldarga","var16",2),0x0B:("starg","var16",2),
0x0C:("ldloc","var16",2),0x0D:("ldloca","var16",2),0x0E:("stloc","var16",2),
0x0F:("localloc",None,0),0x11:("endfilter",None,0),0x12:("unaligned.","i8",1),
0x13:("volatile.",None,0),0x14:("tail.",None,0),0x15:("initobj","tok",4),
0x16:("constrained.","tok",4),0x17:("cpblk",None,0),0x18:("initblk",None,0),
0x1C:("rethrow",None,0),0x1E:("sizeof","tok",4),0x1F:("refanytype",None,0),0x20:("readonly.",None,0),
}

def decode(buf, start, length):
    """Decode CIL bytes buf[start:start+length] into list of dict instrs with il_offset."""
    out = []
    p = start
    end = start + length
    il_off = 0
    while p < end:
        b0 = buf[p]
        if b0 == 0xFE:
            b1 = buf[p+1]
            entry = TWOBYTE.get(b1)
            opsize_hdr = 2
            if entry is None:
                raise ValueError(f"unknown two-byte opcode FE {b1:02x} at file offset {p}")
            mnem, kind, osz = entry
        else:
            entry = SINGLE.get(b0)
            opsize_hdr = 1
            if entry is None:
                raise ValueError(f"unknown single-byte opcode {b0:02x} at file offset {p}")
            mnem, kind, osz = entry
        instr_start_fileoff = p
        instr_il_off = il_off
        p += opsize_hdr
        operand = None
        if kind is None:
            pass
        elif kind == "i8":
            operand = struct.unpack_from("<b", buf, p)[0]; p += 1
        elif kind == "i32":
            operand = struct.unpack_from("<i", buf, p)[0]; p += 4
        elif kind == "i64":
            operand = struct.unpack_from("<q", buf, p)[0]; p += 8
        elif kind == "r4":
            operand = struct.unpack_from("<f", buf, p)[0]; p += 4
        elif kind == "r8":
            operand = struct.unpack_from("<d", buf, p)[0]; p += 8
        elif kind == "var8":
            operand = buf[p]; p += 1
        elif kind == "var16":
            operand = struct.unpack_from("<H", buf, p)[0]; p += 2
        elif kind == "tok":
            operand = struct.unpack_from("<I", buf, p)[0]; p += 4
        elif kind == "br8":
            operand = struct.unpack_from("<b", buf, p)[0]; p += 1
        elif kind == "br32":
            operand = struct.unpack_from("<i", buf, p)[0]; p += 4
        elif kind == "switch":
            n = struct.unpack_from("<I", buf, p)[0]; p += 4
            targets = list(struct.unpack_from(f"<{n}i", buf, p)); p += 4*n
            operand = targets
        else:
            raise ValueError(f"unhandled operand kind {kind}")
        total_len = p - instr_start_fileoff
        out.append({
            "il_offset": instr_il_off,
            "file_offset": instr_start_fileoff,
            "mnemonic": mnem,
            "operand": operand,
            "length": total_len,
        })
        il_off += total_len
    return out


def read_method_body_bytes(exe_path, file_offset, il_size):
    """file_offset from REA is the file offset of the METHOD HEADER (fat or tiny).
    We must skip the header to get to the actual IL bytes. Caller passes header_format
    separately; this helper just reads raw bytes starting at file_offset for inspection."""
    with open(exe_path, "rb") as f:
        f.seek(file_offset)
        return f.read(il_size + 32)  # generous pad; header sizes handled by caller
