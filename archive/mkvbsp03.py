import sys, struct, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *

SRC='/home/claude/vbsp/vbsp_v02.exe'
DST='/home/claude/vbsp/vbsp_v03.exe'

P = PE(SRC)
d = bytearray(P.d)
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
BASE = P.base

big = P.getsec('.bigarr')
BIG_VA = BASE + big['va']
OLD_END = BIG_VA + big['vs']
print(f'.bigarr {BIG_VA:x} vsize {big["vs"]} -> end {OLD_END:x}')

def align(x, a=0x1000): return (x + a - 1) & ~(a-1)

# ---- новая раскладка в хвосте ----
NEW = {}
cur = OLD_END
def place(name, nbytes):
    global cur
    NEW[name] = cur
    cur += align(nbytes)
    print(f'  {name:<12} {NEW[name]:012x}  {nbytes:>12,} -> {align(nbytes):>12,}')
place('dedges',    1_000_000*8)
place('vertchain',   400_000*4)
place('vertedges',   400_000*32)
NEW_END = cur
NEW_VSIZE = NEW_END - BIG_VA
print(f'новый конец {NEW_END:x}, vsize {NEW_VSIZE} ({NEW_VSIZE/1048576:.1f} MB)')

MOVE = {
    0x162cbf000: NEW['dedges'],     # dedges
    0x164c09000: NEW['vertchain'],  # vertexchain
    0x15e69e3a0: NEW['vertedges'],  # per-vertex CUtlVector
}

# ---- собрать все rip-ссылки ----
def func_ins(s,e):
    va=BASE+s; o=P.va2o(va)
    if o is None: return []
    buf=bytes(d[o:o+(e-s)]); out=[]; cur2=0
    while cur2<len(buf):
        got=False
        for ins in md.disasm(buf[cur2:], va+cur2):
            got=True; out.append(ins); cur2=ins.address-va+ins.size
        if not got: cur2+=1
    return out

patched = {k:0 for k in MOVE}
for (s,e) in P.funcs:
    for ins in func_ins(s,e):
        if 'rip' not in ins.op_str: continue
        enc = ins.encoding
        if not enc.disp_size: continue
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
        if not m: continue
        dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
        tgt=ins.address+ins.size+dd
        if tgt in MOVE:
            newdisp = MOVE[tgt] - (ins.address + ins.size)
            assert -2**31 <= newdisp < 2**31, f'disp вне диапазона у {ins.address:x}'
            off = P.va2o(ins.address) + enc.disp_offset
            old = struct.unpack_from('<i', d, off)[0]
            assert old == dd, f'несовпадение disp на {ins.address:x}: {old:x} vs {dd:x}'
            struct.pack_into('<i', d, off, newdisp)
            patched[tgt]+=1
print()
for k,v in patched.items(): print(f'  перенесено ссылок на {k:x}: {v}')

# ---- абсолютные 64/32-битные ссылки в данных (страховка) ----
print()
for old in MOVE:
    pat = struct.pack('<Q', old)
    n = d.count(pat)
    print(f'  абсолютных qword на {old:x} в файле: {n}')

# ---- константа инициализации ----
off = P.va2o(0x140048f26)
assert bytes(d[off:off+5]) == bytes.fromhex('bee0ff1f00'), bytes(d[off:off+5]).hex()
struct.pack_into('<I', d, off+1, (400000-1)*32)
print(f'\n  init-константа 0x1fffe0 -> {(400000-1)*32:#x}')

# ---- правки GetEdge2 ----
fixes = [
    (0x14007bbe5, '470fb75c32fe', '478b5c32fc90'),   # movzx word [r10+r14-2] -> mov dword [r10+r14-4]
    (0x14007bbf0, '4f8b5c97f8',   '4f8b5c57f8'  ),   # r10*4 -> r10*2
    (0x14007bbff, '4b833c9700',   '4b833c5700'  ),
    (0x14007bc06, '4b893497',     '4b893457'    ),
]
print()
for va, oldhex, newhex in fixes:
    o = P.va2o(va)
    assert bytes(d[o:o+len(oldhex)//2]).hex() == oldhex, f'{va:x}: {bytes(d[o:o+8]).hex()}'
    d[o:o+len(newhex)//2] = bytes.fromhex(newhex)
    print(f'  GetEdge2 {va:x}: {oldhex} -> {newhex}')

# ---- расширить секцию ----
pe = P.pe
nsec = struct.unpack_from('<H', d, pe+6)[0]
optsz = struct.unpack_from('<H', d, pe+20)[0]
secoff = pe+24+optsz
for i in range(nsec):
    o = secoff + i*40
    name = bytes(d[o:o+8]).split(b'\0')[0].decode()
    if name == '.bigarr':
        struct.pack_into('<I', d, o+8, NEW_VSIZE)
        print(f'\n  .bigarr VirtualSize -> {NEW_VSIZE:#x}')
soi_off = pe+24+56
old_soi = struct.unpack_from('<I', d, soi_off)[0]
new_soi = align(big['va'] + NEW_VSIZE)
struct.pack_into('<I', d, soi_off, new_soi)
print(f'  SizeOfImage {old_soi:#x} -> {new_soi:#x}')

open(DST,'wb').write(bytes(d))
import hashlib
print(f'\nзаписан {DST}')
print('MD5', hashlib.md5(bytes(d)).hexdigest())
