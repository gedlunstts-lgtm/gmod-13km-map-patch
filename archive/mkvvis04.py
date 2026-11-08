import sys, struct, re, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
SRC='/home/claude/vbsp/vvis_v02.exe'; DST='/home/claude/vbsp/vvis_v04.exe'
P=PE(SRC); d=bytearray(P.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
BASE=P.base
big=P.getsec('.bigarr'); BIG=BASE+big['va']; END=BIG+big['vs']
print(f'.bigarr {BIG:x} vsize {big["vs"]:,} конец {END:x}')
def al(x,a=0x1000): return (x+a-1)&~(a-1)
NEWADDR=END
SIZE=2_000_000*4
print(f'  surfedges -> {NEWADDR:012x}  {SIZE:,} -> {al(SIZE):,}')
NV=(NEWADDR+al(SIZE))-BIG
print(f'новый конец {NEWADDR+al(SIZE):x}, vsize {NV:,} ({NV/1048576:.1f} MB)')
MOVE={0x1517ffda0:NEWADDR}
def fi(s,e):
    va=BASE+s; o=P.va2o(va)
    if o is None: return []
    b=bytes(d[o:o+(e-s)]); out=[]; c=0
    while c<len(b):
        g=False
        for i in md.disasm(b[c:],va+c):
            g=True; out.append(i); c=i.address-va+i.size
        if not g: c+=1
    return out
n=0; sites=[]
for (s,e) in P.funcs:
    for ins in fi(s,e):
        if 'rip' not in ins.op_str: continue
        enc=ins.encoding
        if not enc.disp_size: continue
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',ins.op_str)
        if not m: continue
        dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
        t=ins.address+ins.size+dd
        if t in MOVE:
            nd=MOVE[t]-(ins.address+ins.size)
            off=P.va2o(ins.address)+enc.disp_offset
            assert struct.unpack_from('<i',d,off)[0]==dd
            struct.pack_into('<i',d,off,nd); n+=1
            sites.append((ins.address, ins.mnemonic+' '+ins.op_str))
print(f'\n  перенесено ссылок: {n}')
for a,t in sites: print(f'    {a:012x}  {t}')
print(f'  абсолютных qword: {bytes(d).count(struct.pack("<Q",0x1517ffda0))}')
pe=P.pe; ns=struct.unpack_from('<H',d,pe+6)[0]; op=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+op
for i in range(ns):
    o2=so+i*40
    if bytes(d[o2:o2+8]).split(b'\0')[0]==b'.bigarr': struct.pack_into('<I',d,o2+8,NV)
soi=pe+24+56
old=struct.unpack_from('<I',d,soi)[0]; new=al(big['va']+NV)
struct.pack_into('<I',d,soi,new)
print(f'\n  .bigarr VirtualSize -> {NV:#x}\n  SizeOfImage {old:#x} -> {new:#x}')
open(DST,'wb').write(bytes(d))
print(f'\n{DST}\nMD5 {hashlib.md5(bytes(d)).hexdigest()}')
