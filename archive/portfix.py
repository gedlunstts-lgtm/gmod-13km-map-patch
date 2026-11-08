import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from sigfind import make_sig, find
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
FZ=PE('/home/claude/fz/engine_fz.dll'); V4=PE('/home/claude/fz/engine_v04.dll')
B=PE('/home/claude/fz2/engine_nov_v12.dll'); d=bytearray(B.d)
fz=bytes(FZ.d); v4=bytes(V4.d)
cv=B.getsec('.cave'); CAVE=B.base+cv['va']; CVSZ=cv['vs']; CVRAW=cv['raw']
def o_of(va): return CVRAW+(va-CAVE) if CAVE<=va<CAVE+CVSZ else B.va2o(va)
cur=CAVE
while any(d[o_of(cur):o_of(cur)+64]): cur+=16
cur=(cur+15)&~15
print("pechera svobodna s %012x"%cur)
OLDCAVE=V4.base+V4.getsec('.cave')['va']
GLOB={0x180899dd8:0x18089c958, 0x1807e2998:0x1807e5518}
def locate_code(old_va, src=FZ):
    for nb in (48,40,32,24,16):
        pat,msk,_=make_sig(src,old_va,nb)
        if len(find(src,pat,msk))!=1: continue
        hs=find(B,pat,msk)
        if len(hs)==1: return hs[0]
    return None
h=lambda s: bytes.fromhex(s.replace(' ',''))
# (staryj sajt, staryj stab, dlina staba, novyj sajt, bajt zameny, tip, otkuda brat stab)
S=[(0x1800df8da,0x180e51b10,0x15,0x1800dfeda,12,'jmp',V4),
   (0x1800e9ffd,0x180e51b30,0x0d,0x1800ea60d, 7,'jmp',V4),
   (0x1800f9718,0x180e51b40,0x0d,0x1800f9d28, 7,'jmp',V4),
   (0x180128e3a,0x180e51b50,0x15,0x1801295ca,12,'jmp',V4),
   (0x180115ed2,0x180e519d8,0x22,0x1801164e2, 8,'jmp',FZ)]
for osite,ostub,slen,nsite,n,kind,SRC in S:
    src=bytes(SRC.d)
    blob=bytearray(src[SRC.va2o(ostub):SRC.va2o(ostub)+slen])
    nstub=cur; fixes=0
    import re
    for i in md.disasm(bytes(blob),ostub):
        off=i.address-ostub
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
        if m:
            dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
            t=i.address+i.size+dd
            nt=GLOB.get(t); assert nt, "neizvestnyj global %012x"%t
            struct.pack_into('<i',blob,off+i.encoding.disp_offset, nt-(nstub+off+i.size)); fixes+=1
        elif i.mnemonic in ('jmp','call') and i.op_str.startswith('0x'):
            t=int(i.op_str,16)
            if OLDCAVE<=t<OLDCAVE+0x2000: continue
            if i.size==5:
                nt=(nsite+n) if t==(osite+n) else locate_code(t,SRC)
                assert nt,"ne najden kod %012x"%t
                struct.pack_into('<i',blob,off+1, nt-(nstub+off+i.size)); fixes+=1
    o=o_of(nstub); assert all(x==0 for x in d[o:o+len(blob)]), "pechera zanjata"
    d[o:o+len(blob)]=blob
    op=b'\xe9' if kind=='jmp' else b'\xe8'
    so=B.va2o(nsite); d[so:so+n]=op+struct.pack('<i',nstub-(nsite+5))+b'\x90'*(n-5)
    print("  sajt %012x -> stab %012x (%d bajt, pravok %d)"%(nsite,nstub,len(blob),fixes))
    cur=(nstub+len(blob)+15)&~15
# --- tri sajta s drugimi registrami: sobiraem zanovo
GLOBN=0x18089c958
def cmpglob(at): return h('81 3d')+struct.pack('<i',GLOBN-(at+10))+struct.pack('<I',0x10000)
def build(site,n,pre,hi,post,name):
    global cur
    st=cur; b=bytearray(); b+=pre; b+=cmpglob(st+len(b))
    body=hi+h('c1 e1 10')+h('09 c8')
    b+=h('76')+bytes([len(body)]); b+=body; b+=post
    b+=h('e9')+struct.pack('<i',(site+n)-(st+len(b)+5))
    o=o_of(st); assert all(x==0 for x in d[o:o+len(b)])
    d[o:o+len(b)]=b
    so=B.va2o(site); d[so:so+n]=h('e9')+struct.pack('<i',st-(site+5))+h('90')*(n-5)
    print("  %-26s sajt %012x (%2d) -> stab %012x (%d)"%(name,site,n,st,len(b)))
    cur=(st+len(b)+15)&~15
build(0x18017ffb0, 7, h('0f b7 02'),       h('0f b6 4a 07'),    h('48 8d 0c 80'),       'indeks [rdx]')
build(0x180180108,10, h('0f b7 04 d3'),    h('0f b6 4c d3 07'), h('48 0f bf 5c d3 02'), 'indeks [rbx+rdx*8]')
build(0x180180200, 8, h('0f b7 46 fa'),    h('0f b6 4e 01'),    h('49 8b 6f 70'),       'indeks [rsi-6]')
assert cur<CAVE+CVSZ, "pechera konchilas"
DST='/home/claude/fz2/engine_nov_v13.dll'
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
