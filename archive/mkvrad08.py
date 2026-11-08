import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
SRC='/home/claude/vrad/vrad_v07.exe'; DST='/home/claude/vrad/vrad_v08.exe'
P=PE(SRC); d=bytearray(P.d)
def h(s): return bytes.fromhex(s.replace(' ',''))
SITES=[(0x14006c785,0x1555173b0),(0x14006c855,0x1555173d0),(0x14006c925,0x1555173f0)]
print("vbitye predely vmestimosti vektorov na gran: 0x10000 -> 0x40000\n")
for va,ptr in SITES:
    o=P.va2o(va); cur=bytes(d[o:o+5])
    assert cur==h('3d 00 00 01 00'), "%012x: %s" % (va,cur.hex())
    d[o:o+5]=h('3d 00 00 04 00')
    print("  %012x  cmp eax, 0x10000 -> 0x40000   (vektor %012x, 4 bajta na zapis)" % (va,ptr))
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
