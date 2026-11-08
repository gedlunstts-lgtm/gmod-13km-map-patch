import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
SRC='/home/claude/vbsp/vbsp_v07.exe'; DST='/home/claude/vbsp/vbsp_v08.exe'
P=PE(SRC); d=bytearray(P.d)
# zastrjavshaja ssylka na dedges: lea r9,[162cbf000] -> 164d90000
VA=0x140014050; OLD=0x162cbf000; NEW=0x164d90000
o=P.va2o(VA)
assert bytes(d[o:o+3])==bytes.fromhex('4c8d0d'), bytes(d[o:o+3]).hex()
cur=struct.unpack_from('<i',d,o+3)[0]
assert VA+7+cur==OLD, hex(VA+7+cur)
nd=NEW-(VA+7)
struct.pack_into('<i',d,o+3,nd)
print("  %012x  lea r9, [...]  %012x -> %012x   (dedges)" % (VA,OLD,NEW))
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
