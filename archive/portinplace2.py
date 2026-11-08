import sys, hashlib, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
A=PE('/home/claude/fz/engine_v04.dll')
SRC='/home/claude/fz2/engine_nov_v04.dll'; DST='/home/claude/fz2/engine_nov_v06.dll'
B=PE(SRC); d=bytearray(B.d); da=bytes(A.d)
RX=re.compile(r'\b(?:r[a-z0-9]{1,3}|e[a-z]{2})\b')
#      staryj VA      novyj VA     osz nsz
P=[(0x18007720b,0x18007777b,3,4),(0x1800df3df,0x1800df9df,3,4),
   (0x1800e256b,0x1800e2b7b,4,4),(0x1800e2582,0x1800e2b92,3,4),
   (0x1800e2586,0x1800e2b96,4,4),                                  # add r8,4
   (0x1800ea014,0x1800ea624,4,4),                                  # lea r9,[r9+4]
   (0x1800ea01f,0x1800ea62f,5,6),(0x1800ef43e,0x1800efa4e,3,4),
   (0x1800f5c7b,0x1800f628b,4,5),
   (0x1800f5ca1,0x1800f62b1,3,3),                                  # shl edi,2
   (0x1800f5cb4,0x1800f62c4,4,4),                                  # lea rdi,[rdi+4]
   (0x1800f5cbf,0x1800f62cf,4,5),
   (0x1800f8342,0x1800f8952,3,4),(0x1800f9070,0x1800f9680,3,4),
   (0x180108030,0x180108640,3,4),(0x1801216fb,0x180121e8b,3,4),
   (0x180121731,0x180121ec1,4,5),(0x180121769,0x180121ef9,4,5),
   (0x1801217a4,0x180121f34,4,5),(0x18013d277,0x18013db77,3,4)]
print("pravok:",len(P))
for ova,nva,osz,nsz in P:
    old=da[A.va2o(ova):A.va2o(ova)+osz]
    o=B.va2o(nva); cur=bytes(d[o:o+nsz])
    ia=next(md.disasm(old,ova)); ib=next(md.disasm(cur,nva))
    assert ia.size==osz and ib.size==nsz, "dlina: %s(%d/%d) %s(%d/%d)"%(ia.op_str,ia.size,osz,ib.op_str,ib.size,nsz)
    ra=RX.findall(ia.op_str); rb=RX.findall(ib.op_str)
    SKIP={(0x1800f5ca1,0x1800f62b1)}   # shl edi,2 <-> add rdi,rdi: toт zhe rezultat
    if (ova,nva) in SKIP: ra=rb
    assert ra==rb, "registry: %s vs %s"%(ia.op_str,ib.op_str)
    d[o:o+nsz]=old+b'\x90'*(nsz-osz)
    print("  %012x  %-7s %-32s -> %-7s %s"%(nva,ib.mnemonic,ib.op_str,ia.mnemonic,ia.op_str))
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
