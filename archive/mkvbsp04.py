import sys, struct, re, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *

SRC='/home/claude/vbsp/vbsp_v03.exe'
DST='/home/claude/vbsp/vbsp_v04.exe'
P=PE(SRC); d=bytearray(P.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
BASE=P.base
big=P.getsec('.bigarr'); BIG_VA=BASE+big['va']; OLD_END=BIG_VA+big['vs']
print(f'.bigarr {BIG_VA:x} vsize {big["vs"]:,} конец {OLD_END:x}')
def align(x,a=0x1000): return (x+a-1)&~(a-1)

NEW={}; cur=OLD_END
def place(n,b):
    global cur
    NEW[n]=cur; cur+=align(b)
    print(f'  {n:<20} {NEW[n]:012x}  {b:>12,} -> {align(b):>12,}')
place('vertnormalindices', 1_000_000*2)
place('vertnormals',       1_000_000*12)
NEW_VSIZE=cur-BIG_VA
print(f'новый конец {cur:x}, vsize {NEW_VSIZE:,} ({NEW_VSIZE/1048576:.1f} MB)')

MOVE={0x1505cbc40:NEW['vertnormalindices'], 0x150648c50:NEW['vertnormals']}

def func_ins(s,e):
    va=BASE+s; o=P.va2o(va)
    if o is None: return []
    buf=bytes(d[o:o+(e-s)]); out=[]; c=0
    while c<len(buf):
        got=False
        for ins in md.disasm(buf[c:], va+c):
            got=True; out.append(ins); c=ins.address-va+ins.size
        if not got: c+=1
    return out

cnt={k:0 for k in MOVE}
for (s,e) in P.funcs:
    for ins in func_ins(s,e):
        if 'rip' not in ins.op_str: continue
        enc=ins.encoding
        if not enc.disp_size: continue
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
        if not m: continue
        dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
        t=ins.address+ins.size+dd
        if t in MOVE:
            nd=MOVE[t]-(ins.address+ins.size)
            assert -2**31<=nd<2**31
            off=P.va2o(ins.address)+enc.disp_offset
            assert struct.unpack_from('<i',d,off)[0]==dd
            struct.pack_into('<i',d,off,nd); cnt[t]+=1
print()
for k,v in cnt.items(): print(f'  ссылок перенесено на {k:x}: {v}')
for old in MOVE:
    print(f'  абсолютных qword на {old:x}: {bytes(d).count(struct.pack("<Q",old))}')

# предел индексов нормалей
o=P.va2o(0x140063ee4)
assert bytes(d[o:o+7])==bytes.fromhex('4981f901e80300'), bytes(d[o:o+7]).hex()
struct.pack_into('<I',d,o+3,0xf4241)
print(f'\n  предел vertnormalindices: 0x3e800 -> 0xf4240 (256 000 -> 1 000 000)')

# секция
pe=P.pe; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
for i in range(nsec):
    o2=so+i*40
    if bytes(d[o2:o2+8]).split(b'\0')[0]==b'.bigarr':
        struct.pack_into('<I',d,o2+8,NEW_VSIZE)
soi=pe+24+56
old=struct.unpack_from('<I',d,soi)[0]; new=align(big['va']+NEW_VSIZE)
struct.pack_into('<I',d,soi,new)
print(f'  .bigarr VirtualSize -> {NEW_VSIZE:#x}')
print(f'  SizeOfImage {old:#x} -> {new:#x}')
open(DST,'wb').write(bytes(d))
print(f'\n{DST}\nMD5 {hashlib.md5(bytes(d)).hexdigest()}')
