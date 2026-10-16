"""Read only the selected artifact; validate REA body digests and print compact CIL."""
import datetime
import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2]
record = json.loads((ROOT / 'logs/pass01/02-members.stdout.json').read_text())
data = record['normalized_result']
raw = (ROOT / 'artifacts/baseline/PixelTone.exe').read_bytes()
assert hashlib.sha256(raw).hexdigest() == data['artifact']['sha256']
names = {x['token']: x.get('parent_name', x.get('declaring_type', '')) + '.' + x['name'] for x in data['methods'] + data['member_refs']}
names.update({x['token']: repr(x['value']) for x in data['user_strings']['literals']})
ops = {0x00:'nop', 0x02:'ldarg.0', 0x03:'ldarg.1', 0x04:'ldarg.2', 0x05:'ldarg.3', 0x06:'ldloc.0', 0x07:'ldloc.1', 0x08:'ldloc.2', 0x09:'ldloc.3', 0x0a:'stloc.0', 0x0b:'stloc.1', 0x0c:'stloc.2', 0x0d:'stloc.3', 0x11:'ldloc.s', 0x12:'ldloca.s', 0x13:'stloc.s', 0x15:'ldc.i4.m1', 0x1f:'ldc.i4.s', 0x20:'ldc.i4', 0x25:'dup', 0x28:'call', 0x2a:'ret', 0x2b:'br.s', 0x2c:'brfalse.s', 0x2d:'brtrue.s', 0x2e:'beq.s', 0x2f:'bge.s', 0x30:'bgt.s', 0x31:'ble.s', 0x32:'blt.s', 0x33:'bne.un.s', 0x58:'add', 0x59:'sub', 0x5a:'mul', 0x5b:'div', 0x61:'xor', 0x63:'shr', 0x69:'conv.i4', 0x6f:'callvirt', 0x72:'ldstr', 0x73:'newobj', 0x7a:'throw', 0x8c:'box', 0x8d:'newarr', 0x8e:'ldlen', 0x94:'ldelem.i4', 0x9a:'ldelem.ref', 0x9e:'stelem.i4', 0xa2:'stelem.ref', 0xde:'leave.s'}
ops.update({0x16+i:f'ldc.i4.{i}' for i in range(9)})
out = [f"REA evidence: {record['evidence_id']}", f"SHA256: {data['artifact']['sha256']}"]
for method in data['methods']:
    b = method['body']; off = b['file_offset']
    header = 1 if raw[off]&3 == 2 else ((struct.unpack_from('<H',raw,off)[0] >> 12)*4)
    il = raw[off+header:off+header+b['il_size']]
    assert hashlib.sha256(il).hexdigest() == b['il_sha256']
    out.append(f"\n{method['token']} {method['name']} body_file_offset={off} il_hash_verified=true")
    i = 0; count = 0
    while i < len(il):
        at = i; op=il[i]; i+=1; operand=''; name=ops[op]
        if op in (0x11,0x12,0x13): operand=str(il[i]); i+=1
        elif op == 0x1f: operand=str(struct.unpack_from('<b',il,i)[0]); i+=1
        elif op == 0x20: operand=str(struct.unpack_from('<i',il,i)[0]); i+=4
        elif op in (0x28,0x6f,0x72,0x73,0x8c,0x8d):
            token=f'0x{struct.unpack_from("<I",il,i)[0]:08x}'; i+=4
            operand=token+' '+names.get(token,'')
        elif 0x2b <= op <= 0x33 or op==0xde:
            delta=struct.unpack_from('<b',il,i)[0]; i+=1; operand=str(i+delta)
        out.append(f'  IL_{at:04x} ({at:3d}) {name:<12} {operand}'); count+=1
    assert count==b['decoded_instruction_count']
result='\n'.join(out)+'\n'
(ROOT/'reconstruction/pass01/cil.txt').write_text(result, encoding='utf-8')
with (ROOT/'reconstruction/pass01/actions.jsonl').open('a',encoding='utf-8') as f:
    f.write(json.dumps({'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'action':'static_cil_extract','evidence':record['evidence_id'],'finding':'Artifact SHA256 and all six CIL body hashes verified against REA. Full instruction counts matched. No execution.'})+'\n')
print(result)
