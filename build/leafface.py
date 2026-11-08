"""Dual-mode LEAFFACES: the lump's version field selects 16- or 32-bit
indices, so maps in both formats load.

Usage:  python3 build/leafface.py <engine-in.dll> <engine-out.dll>
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
h=lambda s: bytes.fromhex(s.replace(' ',''))
SRC, DST = sys.argv[1], sys.argv[2]
B=PE(SRC); d=bytearray(B.d)
cv=B.getsec('.cave'); CAVE=B.base+cv['va']; CVSZ=cv['vs']; CVRAW=cv['raw']
def o_of(va): return CVRAW+(va-CAVE) if CAVE<=va<CAVE+CVSZ else B.va2o(va)
cur=CAVE
while any(d[o_of(cur):o_of(cur)+64]): cur+=16
cur=(cur+15)&~15
print("pechera svobodna s %012x"%cur)
def wr(va,old,new,what):
    o=o_of(va); assert bytes(d[o:o+len(old)])==old, "%012x: %s != %s"%(va,bytes(d[o:o+len(old)]).hex(),old.hex())
    d[o:o+len(new)]=new; print("  %012x  %s"%(va,what))

# 1) proverka dliny: vernjom stokovuju (kratnost 2) - nashi lampy kratny 4, projdut obe
wr(0x1801179a0, h('a8 03'), h('a8 01'), 'proverka dliny: snova kratnost 2')

VER='24 48'   # [rsp+0x48]
# 2) shag: shr rbx,2 pri versii 1, inache shr rbx,1   (10 bajt na sajte)
st=cur
stub =h('48 c7 c1 ff ff ff ff')                 # mov rcx, -1
stub+=h('83 7c 24 48 01')                       # cmp dword [rsp+0x48], 1
stub+=h('75 06')                                # jne -> v0  (6, a ne 5: shr+jmp = 4+2)
stub+=h('48 c1 eb 02')                          # shr rbx, 2
stub+=h('eb 03')                                # jmp back
stub+=h('48 d1 eb')                             # v0: shr rbx, 1
stub+=h('e9')+struct.pack('<i', 0x1801179c8-(st+len(stub)+5))
o=o_of(st); assert all(x==0 for x in d[o:o+len(stub)])
d[o:o+len(stub)]=stub
wr(0x1801179be, h('31 c9 48 ff c9 48 c1 eb 02 90'),
   h('e9')+struct.pack('<i', st-(0x1801179be+5))+h('90')*5, 'shag -> tramplin')
print("    stab shaga %012x (%d bajt)"%(st,len(stub)))
cur=(st+len(stub)+15)&~15

# 3) chtenie: 4 bajta pri versii 1, inache 2   (sajt 10 bajt: chtenie 4 + cmp 6)
st=cur
stub =h('83 7c 24 48 01')                       # cmp dword [rsp+0x48], 1
stub+=h('75 05')                                # jne -> v0
stub+=h('8b 1c be')                             # mov ebx, dword [rsi+rdi*4]
stub+=h('eb 04')                                # jmp cont
stub+=h('0f b7 1c 7e')                          # v0: movzx ebx, word [rsi+rdi*2]
stub+=h('41 3b 98 d8 00 00 00')                 # cont: cmp ebx, [r8+0xd8]
stub+=h('e9')+struct.pack('<i', 0x180117a3b-(st+len(stub)+5))
o=o_of(st); assert all(x==0 for x in d[o:o+len(stub)])
d[o:o+len(stub)]=stub
wr(0x180117a30, h('8b 1c be 90 41 3b 98 d8 00 00 00'),
   h('e9')+struct.pack('<i', st-(0x180117a30+5))+h('90')*6, 'chtenie -> tramplin')
print("    stab chtenija %012x (%d bajt)"%(st,len(stub)))
cur=(st+len(stub)+15)&~15
assert cur<CAVE+CVSZ

open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
