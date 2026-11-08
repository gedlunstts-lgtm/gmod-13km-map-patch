import sys, struct, hashlib, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
h=lambda s: bytes.fromhex(s.replace(' ',''))
SRC='/home/claude/fz2/engine_nov_v03.dll'; DST='/home/claude/fz2/engine_nov_v04.dll'
B=PE(SRC); d=bytearray(B.d)
cv=B.getsec('.cave'); CAVE=B.base+cv['va']; CVSZ=cv['vs']; CVRAW=cv['raw']
def o_of(va): return CVRAW+(va-CAVE) if CAVE<=va<CAVE+CVSZ else B.va2o(va)
cur=CAVE
while any(d[o_of(cur):o_of(cur)+64]): cur+=16
cur=(cur+15)&~15
print("svobodnaja pechera s %012x"%cur)
GLOB=0x18089c958           # schjotchik, sravnivaemyj s 0x10000

def cmpglob(at):
    """cmp dword [rip+X], 0x10000  - 10 bajt, at = adres etoj instrukcii"""
    return h('81 3d')+struct.pack('<i', GLOB-(at+10))+struct.pack('<I',0x10000)

def build(site, n, pre, hi, post, name):
    """pre - ishodnoe chtenie; hi - chtenie starshego bajta; post - hvost"""
    global cur
    st=cur; b=bytearray()
    b+=pre
    b+=cmpglob(st+len(b))
    body=hi+h('c1 e1 10')+h('09 c8')           # shl ecx,0x10 ; or eax,ecx
    b+=h('76')+bytes([len(body)])              # jbe -> propustit
    b+=body
    b+=post
    back=site+n
    b+=h('e9')+struct.pack('<i', back-(st+len(b)+5))
    o=o_of(st); assert all(x==0 for x in d[o:o+len(b)])
    d[o:o+len(b)]=b
    so=B.va2o(site)
    d[so:so+n]=h('e9')+struct.pack('<i', st-(site+5))+h('90')*(n-5)
    print("  %-28s sajt %012x (%2d bajt) -> stab %012x (%d bajt)"%(name,site,n,st,len(b)))
    cur=(st+len(b)+15)&~15

# 1) movzx eax, word [rdx] ; lea rcx,[rax+rax*4]
build(0x18017ffb0, 7, h('0f b7 02'), h('0f b6 4a 07'), h('48 8d 0c 80'), 'indeks cherez [rdx]')
# 2) movzx eax, word [rbx+rdx*8] ; movsx rbx, word [rbx+rdx*8+2]
build(0x180180108, 10, h('0f b7 04 d3'), h('0f b6 4c d3 07'), h('48 0f bf 5c d3 02'), 'indeks cherez [rbx+rdx*8]')
# 3) movzx eax, word [rsi-6] ; mov rbp,[r15+0x70]
build(0x180180200, 8, h('0f b7 46 fa'), h('0f b6 4e 01'), h('49 8b 6f 70'), 'indeks cherez [rsi-6]')
assert cur<CAVE+CVSZ
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
