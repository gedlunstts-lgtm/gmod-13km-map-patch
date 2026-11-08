import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
SRC='/home/claude/vbsp/vvis_v05.exe'; DST='/home/claude/vbsp/vvis_v06.exe'
P=PE(SRC); d=bytearray(P.d)
VA=0x14000ff29; OLD=0x1517ffda0; NEW=0x154934000
o=P.va2o(VA)
assert bytes(d[o:o+3])==bytes.fromhex('4c8d05'), bytes(d[o:o+3]).hex()
cur=struct.unpack_from('<i',d,o+3)[0]
assert VA+7+cur==OLD, hex(VA+7+cur)
struct.pack_into('<i',d,o+3,NEW-(VA+7))
print("  %012x  lea r8, [...]  %012x -> %012x   (dsurfedges)" % (VA,OLD,NEW))
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
