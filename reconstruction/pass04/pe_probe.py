import struct, sys

path = r"C:\HFF\MDI\Dysphasia\artifacts\protected-p1p2p3\PixelTone.exe"
with open(path, "rb") as f:
    data = f.read()

print("file length", len(data))

# DOS header
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
print("e_lfanew", hex(e_lfanew))
pe_off = e_lfanew
assert data[pe_off:pe_off+4] == b"PE\x00\x00"
machine, nsec = struct.unpack_from("<HH", data, pe_off+4)
print("machine", hex(machine), "nsections", nsec)
opt_hdr_size = struct.unpack_from("<H", data, pe_off+20)[0]
coff_off = pe_off + 24
opt_off = coff_off
# optional header magic
magic = struct.unpack_from("<H", data, opt_off)[0]
print("optional header magic", hex(magic))
sect_table_off = opt_off + opt_hdr_size
print("section table offset", sect_table_off)

sections = []
for i in range(nsec):
    off = sect_table_off + i*40
    name = data[off:off+8].rstrip(b"\x00").decode(errors="replace")
    virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off+8)
    sections.append((name, virt_addr, virt_size, raw_ptr, raw_size))
    print(f"section {name!r}: VA=0x{virt_addr:x} VSize=0x{virt_size:x} RawPtr=0x{raw_ptr:x} RawSize=0x{raw_size:x}")

def rva2off(rva):
    for name, va, vsize, rptr, rsize in sections:
        if va <= rva < va + max(vsize, rsize):
            return rptr + (rva - va)
    raise ValueError(f"RVA 0x{rva:x} not mapped")

# CLI header at file offset 512 per REA (data directory 15 in optional header for pe32+)
# optional header pe32+ : data directories start at opt_off + 112 (for PE32+) each 8 bytes, 16 dirs,
# CLI header dir is index 14 (0-based)
is_pe32plus = (magic == 0x20b)
if is_pe32plus:
    datadir_off = opt_off + 112
else:
    datadir_off = opt_off + 96
cli_dir_off = datadir_off + 14*8
cli_rva, cli_size = struct.unpack_from("<II", data, cli_dir_off)
print("CLI header RVA", hex(cli_rva), "size", cli_size)
cli_file_off = rva2off(cli_rva)
print("CLI header file offset", cli_file_off)

cb, major, minor, pad, flags, entrytok = struct.unpack_from("<IHHIII", data, cli_file_off)
print("cli cb", cb, "ver", major, minor, "flags", flags, "entrytok", hex(entrytok))
meta_rva, meta_size = struct.unpack_from("<II", data, cli_file_off+8)
print("metadata rva", hex(meta_rva), "size", meta_size)
meta_off = rva2off(meta_rva)
print("metadata file offset", meta_off)

# metadata root
sig = struct.unpack_from("<I", data, meta_off)[0]
print("meta sig", hex(sig))
maj, minr = struct.unpack_from("<HH", data, meta_off+4)
reserved = struct.unpack_from("<I", data, meta_off+8)[0]
verlen = struct.unpack_from("<I", data, meta_off+12)[0]
verstr = data[meta_off+16:meta_off+16+verlen].rstrip(b"\x00").decode(errors="replace")
print("version string", verstr)
p = meta_off + 16 + verlen
flags2, nstreams = struct.unpack_from("<HH", data, p)
p += 4
print("nstreams", nstreams)
streams = []
for i in range(nstreams):
    soff, ssize = struct.unpack_from("<II", data, p)
    p += 8
    # name is null terminated, padded to 4 bytes
    namestart = p
    nameend = data.index(b"\x00", namestart)
    sname = data[namestart:nameend].decode()
    padded_len = ((nameend - namestart + 1) + 3) & ~3
    p = namestart + padded_len
    streams.append((sname, soff, ssize))
    print(f"stream {sname!r} offset(rel)=0x{soff:x} size=0x{ssize:x} abs_file_off=0x{meta_off+soff:x}")


# ---- Parse #~ tables stream ----
tilde_name, tilde_rel, tilde_size = [s for s in streams if s[0]=="#~"][0]
tilde_off = meta_off + tilde_rel
strings_name, strings_rel, strings_size = [s for s in streams if s[0]=="#Strings"][0]
strings_off = meta_off + strings_rel
blob_name, blob_rel, blob_size = [s for s in streams if s[0]=="#Blob"][0]
blob_off = meta_off + blob_rel
guid_name, guid_rel, guid_size = [s for s in streams if s[0]=="#GUID"][0]
guid_off = meta_off + guid_rel

reserved0, major_t, minor_t, heap_sizes, reserved1 = struct.unpack_from("<IBBBB", data, tilde_off)
valid = struct.unpack_from("<Q", data, tilde_off+8)[0]
sorted_ = struct.unpack_from("<Q", data, tilde_off+16)[0]
print("heap_sizes flag", bin(heap_sizes))
p = tilde_off + 24

table_names = {
 0x00:"Module",0x01:"TypeRef",0x02:"TypeDef",0x04:"Field",0x06:"MethodDef",
 0x08:"Param",0x09:"InterfaceImpl",0x0A:"MemberRef",0x0B:"Constant",0x0C:"CustomAttribute",
 0x0D:"FieldMarshal",0x0E:"DeclSecurity",0x0F:"ClassLayout",0x10:"FieldLayout",
 0x11:"StandAloneSig",0x12:"EventMap",0x14:"Event",0x15:"PropertyMap",0x17:"Property",
 0x18:"MethodSemantics",0x19:"MethodImpl",0x1A:"ModuleRef",0x1B:"TypeSpec",0x1C:"ImplMap",
 0x1D:"FieldRVA",0x20:"Assembly",0x21:"AssemblyProcessor",0x22:"AssemblyOS",
 0x23:"AssemblyRef",0x24:"AssemblyRefProcessor",0x25:"AssemblyRefOS",0x26:"File",
 0x27:"ExportedType",0x28:"ManifestResource",0x29:"NestedClass",0x2A:"GenericParam",
 0x2B:"MethodSpec",0x2C:"GenericParamConstraint",
}

present = [i for i in range(64) if (valid >> i) & 1]
row_counts = {}
for idx in present:
    cnt = struct.unpack_from("<I", data, p)[0]
    p += 4
    row_counts[idx] = cnt
    print(f"table 0x{idx:02x} {table_names.get(idx,'?')}: rows={cnt}")

print("rows start at", hex(p))

str_idx_size = 4 if (heap_sizes & 0x01) else 2
guid_idx_size = 4 if (heap_sizes & 0x02) else 2
blob_idx_size = 4 if (heap_sizes & 0x04) else 2
print("str_idx_size", str_idx_size, "guid_idx_size", guid_idx_size, "blob_idx_size", blob_idx_size)

def idx_size_for_table(t):
    return 4 if row_counts.get(t,0) > 0xFFFF else 2

def coded_idx_size(tables_bits):
    # tables_bits: list of table ids that can be targets; need tag bits = ceil(log2(len(tables)))
    import math
    tagbits = max(1, (len(tables_bits)-1).bit_length())
    maxrows = max((row_counts.get(t,0) for t in tables_bits), default=0)
    return 4 if (maxrows << tagbits) > 0xFFFF else 2

# define coded token table sets per ECMA-335 II.24.2.6
TypeDefOrRef = [0x02,0x01,0x1B]
HasConstant = [0x04,0x08,0x17]
HasCustomAttribute = list(range(0x00,0x2D))  # not exact but unused precisely here
CustomAttributeType = [0x06,0x0A,0x01,0x1B,0x1B]  # approx; unused precisely
HasFieldMarshal = [0x04,0x08]
HasDeclSecurity = [0x02,0x06,0x20]
MemberRefParent = [0x02,0x01,0x1A,0x06,0x1B]
HasSemantics = [0x14,0x17]
MethodDefOrRef = [0x06,0x0A]
MemberForwarded = [0x04,0x06]
Implementation = [0x26,0x27,0x23]
CustomAttributeType2 = [0x02,0x06,0x0A,0x1B,0x00]
ResolutionScope = [0x00,0x01,0x23,0x1A]
TypeOrMethodDef = [0x02,0x06]

row_sizes = {}
for t in present:
    size = 0
    name = table_names.get(t)
    if name == "Module":
        size = 2 + str_idx_size + 3*guid_idx_size
    elif name == "TypeRef":
        size = coded_idx_size(ResolutionScope) + 2*str_idx_size
    elif name == "TypeDef":
        size = 4 + 2*str_idx_size + coded_idx_size(TypeDefOrRef) + idx_size_for_table(0x04) + idx_size_for_table(0x06)
    elif name == "Field":
        size = 2 + str_idx_size + blob_idx_size
    elif name == "MethodDef":
        size = 4 + 2 + 2 + str_idx_size + blob_idx_size + idx_size_for_table(0x08)
    elif name == "Param":
        size = 2 + 2 + str_idx_size
    elif name == "InterfaceImpl":
        size = idx_size_for_table(0x02) + coded_idx_size(TypeDefOrRef)
    elif name == "MemberRef":
        size = coded_idx_size(MemberRefParent) + str_idx_size + blob_idx_size
    elif name == "Constant":
        size = 1+1 + coded_idx_size(HasConstant) + blob_idx_size
    elif name == "CustomAttribute":
        size = coded_idx_size(list(range(0,0x2D))) # placeholder; recompute below properly
    elif name == "ClassLayout":
        size = 2 + 4 + idx_size_for_table(0x02)
    elif name == "FieldLayout":
        size = 4 + idx_size_for_table(0x04)
    elif name == "StandAloneSig":
        size = blob_idx_size
    elif name == "EventMap":
        size = idx_size_for_table(0x02) + idx_size_for_table(0x14)
    elif name == "Event":
        size = 2 + str_idx_size + coded_idx_size(TypeDefOrRef)
    elif name == "PropertyMap":
        size = idx_size_for_table(0x02) + idx_size_for_table(0x17)
    elif name == "Property":
        size = 2 + str_idx_size + blob_idx_size
    elif name == "MethodSemantics":
        size = 2 + idx_size_for_table(0x06) + coded_idx_size(HasSemantics)
    elif name == "MethodImpl":
        size = idx_size_for_table(0x02) + coded_idx_size(MethodDefOrRef)*2
    elif name == "ModuleRef":
        size = str_idx_size
    elif name == "TypeSpec":
        size = blob_idx_size
    elif name == "ImplMap":
        size = 2 + coded_idx_size(MemberForwarded) + str_idx_size + idx_size_for_table(0x1A)
    elif name == "FieldRVA":
        size = 4 + idx_size_for_table(0x04)
    elif name == "Assembly":
        size = 4+8+4+blob_idx_size+2*str_idx_size
    elif name == "AssemblyRef":
        size = 8+4+blob_idx_size+2*str_idx_size+blob_idx_size
    elif name == "File":
        size = 4+str_idx_size+blob_idx_size
    elif name == "ExportedType":
        size = 4+4+2*str_idx_size+coded_idx_size(Implementation)
    elif name == "ManifestResource":
        size = 4+4+str_idx_size+coded_idx_size(Implementation)
    elif name == "NestedClass":
        size = idx_size_for_table(0x02)*2
    elif name == "GenericParam":
        size = 2+2+coded_idx_size(TypeOrMethodDef)+str_idx_size
    elif name == "MethodSpec":
        size = idx_size_for_table(0x06)+blob_idx_size
    elif name == "GenericParamConstraint":
        size = idx_size_for_table(0x2A)+coded_idx_size(TypeDefOrRef)
    else:
        size = 0
    row_sizes[t] = size

# fix CustomAttribute properly: HasCustomAttribute coded index covers ~20 tables -> tag bits = 5
HasCustomAttributeList = list(range(0,0x2D))
def coded_idx_size_bits(ntables):
    tagbits = max(1,(ntables-1).bit_length())
    return tagbits
tagbits_hca = coded_idx_size_bits(len(HasCustomAttributeList))
# max row count among those tables
maxrows_hca = max((row_counts.get(t,0) for t in HasCustomAttributeList), default=0)
hca_size = 4 if (maxrows_hca << tagbits_hca) > 0xFFFF else 2
row_sizes[0x0C] = coded_idx_size_bits  # placeholder, fixed below
ca_parent_size = hca_size
ca_ctor_tagbits = coded_idx_size_bits(len([0x06,0x0A]))
maxrows_cat = max(row_counts.get(0x06,0),row_counts.get(0x0A,0))
ca_ctor_size = 4 if (maxrows_cat << ca_ctor_tagbits) > 0xFFFF else 2
row_sizes[0x0C] = ca_parent_size + ca_ctor_size + blob_idx_size

print("row sizes:", {table_names[t]: row_sizes[t] for t in present})

offsets = {}
cur = p
for t in present:
    offsets[t] = cur
    cur += row_sizes[t]*row_counts[t]

for t in present:
    print(f"{table_names[t]} rows start at file offset 0x{offsets[t]:x} ({offsets[t]}) row_size={row_sizes[t]}")

print("END OF TABLES at", hex(cur), cur)

# FieldRVA row
fieldrva_off = offsets[0x1D]
rva_val, field_idx = struct.unpack_from("<IH", data, fieldrva_off)
print("FieldRVA: RVA=0x%x field_idx=%d" % (rva_val, field_idx))
fieldrva_fileoff = rva2off(rva_val)
print("FieldRVA data file offset", hex(fieldrva_fileoff), fieldrva_fileoff)

# ClassLayout row (gives size of the struct type used for the byte blob)
cl_off = offsets[0x0F]
packing, class_size, parent_typedef = struct.unpack_from("<HIH", data, cl_off)
print("ClassLayout: packing=%d class_size=%d parent_typedef_rid=%d" % (packing, class_size, parent_typedef))

blob = data[fieldrva_fileoff: fieldrva_fileoff+class_size]
print("blob length", len(blob))
print("blob hex:", blob.hex())
