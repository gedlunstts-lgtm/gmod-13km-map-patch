import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from refs import Refs
SRC='/home/claude/vbsp/vbsp_v08.exe'; DST='/home/claude/vbsp/vbsp_v09.exe'
P=PE(SRC); d=bytearray(P.d); R=Refs(P)
OLD=0x15e69e3a0; SZ=0x200000; DELTA=0x701ac60
print("zakryvaju utechku: diapazon %012x..%012x, delta %+#x" % (OLD,OLD+SZ,DELTA))
n=0
for va,(off,dd,tg,mn,sz) in sorted(R.map.items()):
    if not (OLD<=tg<OLD+SZ): continue
    nt=tg+DELTA; nd=nt-(va+sz)
    assert -2**31<=nd<2**31
    assert struct.unpack_from('<i',d,off)[0]==dd
    struct.pack_into('<i',d,off,nd); n+=1
    print("   %012x  %-7s  %012x -> %012x" % (va,mn,tg,nt))
print("ispravleno: %d" % n)
assert n==1, "ozhidalas rovno odna ssylka"
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
