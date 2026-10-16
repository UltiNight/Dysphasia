import sys, json
sys.path.insert(0, r"C:\HFF\MDI\Dysphasia\reconstruction\pass04")
from cil_decoder import decode

EXE = r"C:\HFF\MDI\Dysphasia\artifacts\protected-p1p2p3\PixelTone.exe"

with open(EXE, "rb") as f:
    data = f.read()

methods = [
    # token, name, header_format, file_offset(header start), il_size
    ("0x06000001", "m_4e09ee408f", "fat", 592, 145),
    ("0x06000002", "m_b2ece2c34c", "tiny", 749, 38),
    ("0x06000003", "m_b3c4f3c803", "fat", 788, 432),
    ("0x06000004", "m_0481f84d57", "fat", 1232, 144),
    ("0x06000005", "m_22283830b7", "fat", 1388, 213),
    ("0x06000006", "m_ec38e2401a", "fat", 1616, 728),
    ("0x06000007", ".cctor",      "tiny", 2384, 27),
    ("0x06000008", "m_5558f5ab53", "fat", 2412, 76),
]

for tok, name, fmt, hdr_off, il_size in methods:
    il_start = hdr_off + (1 if fmt == "tiny" else 12)
    instrs = decode(data, il_start, il_size)
    print(f"\n=== {tok} {name} ({fmt}, il_start=0x{il_start:x}={il_start}, il_size={il_size}) ===")
    for ins in instrs:
        op = ins["operand"]
        next_off = ins["il_offset"] + ins["length"]
        extra = ""
        m = ins["mnemonic"]
        if m in ("br","br.s","brfalse","brfalse.s","brtrue","brtrue.s","beq","beq.s","bge","bge.s",
                  "bgt","bgt.s","ble","ble.s","blt","blt.s","bne.un","bne.un.s","bge.un","bge.un.s",
                  "bgt.un","bgt.un.s","ble.un","ble.un.s","blt.un","blt.un.s","leave","leave.s"):
            extra = f"  -> IL_{next_off+op:04d}"
        elif m == "switch":
            tg = [next_off+t for t in op]
            extra = f"  -> {tg}"
        opstr = "" if op is None else (str(op) if not isinstance(op, list) else "")
        print(f"  IL_{ins['il_offset']:04d} (len{ins['length']}): {m:14s} {opstr:<10}{extra}")
