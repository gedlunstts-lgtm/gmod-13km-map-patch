import sys, struct, hashlib, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from sigfind import make_sig, find
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
FZ=PE('/home/claude/fz/engine_fz.dll')
B=PE('/home/claude/fz2/engine_nov_v13.dll'); d=bytearray(B.d)
fz=bytes(FZ.d)
cv=B.getsec('.cave'); CAVE=B.base+cv['va']; CVSZ=cv['vs']; CVRAW=cv['raw']
def o_of(va): return CVRAW+(va-CAVE) if CAVE<=va<CAVE+CVSZ else B.va2o(va)
cur=CAVE
while any(d[o_of(cur):o_of(cur)+64]): cur+=16
cur=(cur+15)&~15
# --- 1. konstanty
DATA={}
blocks=[(0x180e500e0,16),(0x180e519b0,12)]
for base,ln in blocks:
    dst=cur
    d[o_of(dst):o_of(dst)+ln]=fz[FZ.va2o(base):FZ.va2o(base)+ln]
    for k in range(0,ln,4): DATA[base+k]=dst+k
    print("konstanty %012x..%012x -> %012x"%(base,base+ln-1,dst))
    cur=(dst+ln+15)&~15
GLOB={0x1807e2998:0x1807e5518, 0x180899dd8:0x18089c958}
def locate_code(old_va):
    for nb in (48,40,32,24,16):
        pat,msk,_=make_sig(FZ,old_va,nb)
        if len(find(FZ,pat,msk))!=1: continue
        hs=find(B,pat,msk)
        if len(hs)==1: return hs[0]
    return None
OLDC=FZ.base+FZ.getsec('.cave')['va']
# (staryj sajt, staryj stab, dlina staba, novyj sajt, bajt, tip)
S=[(0x180114605,0x180e51800,0x121,0x180114c15, 5,'call'),
   (0x1801177f6,0x180e51921,0x09f,0x180117e06, 8,'jmp'),
   (0x18017eb63,0x180e519c0,0x012,0x18017f5e3,20,'jmp'),
   (0x1802109a2,0x180e50150,0x00e,0x1802119b2, 6,'jmp'),
   (0x180210b28,0x180e50160,0x00e,0x180211b38, 6,'jmp'),
   (0x180210caa,0x180e50170,0x012,0x180211cba, 7,'jmp'),
   (0x1802127ab,0x180e500f0,0x020,0x1802137bb, 8,'jmp'),
   (0x18021299e,0x180e50120,0x01d,0x1802139ae, 8,'jmp')]
for osite,ostub,slen,nsite,n,kind in S:
    blob=bytearray(fz[FZ.va2o(ostub):FZ.va2o(ostub)+slen])
    nstub=cur; fx=0
    for i in md.disasm(bytes(blob),ostub):
        off=i.address-ostub
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
        if m:
            dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
            t=i.address+i.size+dd
            nt=DATA.get(t) or GLOB.get(t)
            assert nt, "neizvestnaja cel %012x iz stabа %012x"%(t,ostub)
            struct.pack_into('<i',blob,off+i.encoding.disp_offset, nt-(nstub+off+i.size)); fx+=1
        elif i.mnemonic in ('jmp','call') and i.op_str.startswith('0x'):
            t=int(i.op_str,16)
            if OLDC<=t<OLDC+0x2000: continue
            if i.size==5:
                nt=(nsite+n) if t==(osite+n) else locate_code(t)
                assert nt, "ne najden kod %012x"%t
                struct.pack_into('<i',blob,off+1, nt-(nstub+off+i.size)); fx+=1
    o=o_of(nstub); assert all(x==0 for x in d[o:o+len(blob)]), "pechera zanjata na %012x"%nstub
    d[o:o+len(blob)]=blob
    op=b'\xe9' if kind=='jmp' else b'\xe8'
    so=B.va2o(nsite); d[so:so+n]=op+struct.pack('<i',nstub-(nsite+5))+b'\x90'*(n-5)
    print("  sajt %012x -> stab %012x  (%3d bajt, pravok %d)"%(nsite,nstub,len(blob),fx))
    cur=(nstub+len(blob)+15)&~15
print("pechera ispolzovano do %012x iz %012x"%(cur,CAVE+CVSZ))
assert cur<CAVE+CVSZ
DST='/home/claude/fz2/engine_nov_v14.dll'
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
