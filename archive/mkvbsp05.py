import sys, struct, re, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *

SRC='/home/claude/vbsp/vbsp_v04.exe'
DST='/home/claude/vbsp/vbsp_v05.exe'
NEWMAX=262144                      # 0x40000, bylo 65536
P=PE(SRC); d=bytearray(P.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
BASE=P.base
big=P.getsec('.bigarr'); BIG_VA=BASE+big['va']; OLD_END=BIG_VA+big['vs']
print('.bigarr %x vsize %d konec %x' % (BIG_VA,big['vs'],OLD_END))
def align(x,a=0x1000): return (x+a-1)&~(a-1)

NEW={}; cur=OLD_END
def place(n,b):
    global cur
    NEW[n]=cur; cur+=align(b)
    print('  %-14s %012x  %12d bajt' % (n,NEW[n],b))
SZ=NEWMAX*56
place('faces',     SZ)
place('faces_hdr', SZ)
place('origfaces', SZ)
NEW_VSIZE=cur-BIG_VA
print('novyj konec %x, vsize %d (%.1f MB)' % (cur,NEW_VSIZE,NEW_VSIZE/1048576))

MOVE={0x151026d60:NEW['faces'], 0x1513a6d90:NEW['faces_hdr'], 0x150b76d20:NEW['origfaces']}

def fins(s,e):
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
    for ins in fins(s,e):
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
for k,v in cnt.items(): print('  perenes ssylok na %x: %d' % (k,v))
for old in MOVE:
    n=bytes(d).count(struct.pack("<Q",old))
    print('  absoljutnyh qword na %x: %d' % (old,n))

print()
for addr,nm in ((0x14007ba5c,'numorigfaces'),(0x14007be03,'numfaces')):
    o=P.va2o(addr)
    cur_b=bytes(d[o:o+6])
    assert cur_b==bytes.fromhex('483d00000100'), '%x: %s' % (addr,cur_b.hex())
    struct.pack_into('<I',d,o+2,NEWMAX)
    print('  %012x  cmp rax, 0x10000 -> 0x%x   (%s)' % (addr,NEWMAX,nm))

pe=P.pe; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
for i in range(nsec):
    o2=so+i*40
    if bytes(d[o2:o2+8]).split(b'\0')[0]==b'.bigarr':
        struct.pack_into('<I',d,o2+8,NEW_VSIZE)
soi=pe+24+56
old=struct.unpack_from('<I',d,soi)[0]; new=align(big['va']+NEW_VSIZE)
struct.pack_into('<I',d,soi,new)
print('  .bigarr VirtualSize -> %#x' % NEW_VSIZE)
print('  SizeOfImage %#x -> %#x' % (old,new))
open(DST,'wb').write(bytes(d))
print('\n%s\nMD5 %s' % (DST, hashlib.md5(bytes(d)).hexdigest()))
