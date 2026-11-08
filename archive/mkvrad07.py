import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
SRC='/home/claude/vrad/vrad_v06.exe'; DST='/home/claude/vrad/vrad_v07.exe'
P=PE(SRC); d=bytearray(P.d)
def h(s): return bytes.fromhex(s.replace(' ',''))
def put(va,old,new,what):
    assert len(old)==len(new),(hex(va),len(old),len(new))
    o=P.va2o(va); cur=bytes(d[o:o+len(old)])
    assert cur==old,"%012x: %s != %s"%(va,cur.hex(),old.hex())
    d[o:o+len(new)]=new
    print("  %012x  %-26s -> %-26s  %s" % (va,old.hex(),new.hex(),what))
print("BuildVisLeafs (%012x): ramka 0x20078 -> 0x80078\n" % 0x140066340)
put(0x14006634c, h('b8 78 00 02 00'),           h('b8 78 00 08 00'),           'razmer ramki')
put(0x140066715, h('48 81 c4 78 00 02 00'),     h('48 81 c4 78 00 08 00'),     'epilog')
put(0x140066382, h('48 8d 8c 24 60 00 01 00'),  h('48 8d 8c 24 60 00 04 00'),  'bufer A: baza 0x10060 -> 0x40060')
put(0x1400664d7, h('80 bc 0c 60 00 01 00 00'),  h('80 bc 0c 60 00 04 00 00'),  'bufer A: chtenie')
put(0x1400664e1, h('c6 84 0c 60 00 01 00 01'),  h('c6 84 0c 60 00 04 00 01'),  'bufer A: zapis')
put(0x140066359, h('66 0f 29 b4 24 60 00 02 00'),h('66 0f 29 b4 24 60 00 08 00'),'sohranenie xmm6')
put(0x14006670d, h('0f 28 b4 24 60 00 02 00'),  h('0f 28 b4 24 60 00 08 00'),  'vosstanovlenie xmm6')
put(0x14006658b, h('8b 84 24 e8 00 02 00'),     h('8b 84 24 e8 00 08 00'),     'argument vyzyvajushchego 6')
put(0x140066596, h('48 8b 84 24 e0 00 02 00'),  h('48 8b 84 24 e0 00 08 00'),  'argument vyzyvajushchego 5')
put(0x1400666cb, h('8b 84 24 e8 00 02 00'),     h('8b 84 24 e8 00 08 00'),     'argument 6 (vtoroe mesto)')
put(0x1400666d6, h('48 8b 84 24 e0 00 02 00'),  h('48 8b 84 24 e0 00 08 00'),  'argument 5 (vtoroe mesto)')
pe=P.pe
so=pe+24+72
old=struct.unpack_from('<Q',d,so)[0]
NEW=8*1024*1024
if old<NEW:
    struct.pack_into('<Q',d,so,NEW)
    print("\n  SizeOfStackReserve %s -> %s bajt" % (format(old,','),format(NEW,',')))
else:
    print("\n  SizeOfStackReserve uzhe %s bajt, ostavljaju" % format(old,','))
print("  SizeOfStackCommit  %s bajt" % format(struct.unpack_from('<Q',d,pe+24+80)[0],','))
print("\n  novaja raskladka ramki:")
print("     [0x00000 .. 0x00060)  prochie lokalnye")
print("     [0x00060 .. 0x40060)  bufer B   262 144 bajt")
print("     [0x40060 .. 0x80060)  bufer A   262 144 bajt")
print("     [0x80060 .. 0x80070)  xmm6")
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
