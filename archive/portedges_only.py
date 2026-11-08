import sys, struct, hashlib, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from sigfind import make_sig, find
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
A=PE('/home/claude/fz/engine_v04.dll')
SRC='/home/claude/fz2/engine_nov_v02.dll'; DST='/home/claude/fz2/engine_nov_v08.dll'
B=PE(SRC); d=bytearray(B.d); db=bytes(B.d); da=bytes(A.d)
cv=B.getsec('.cave'); CAVE=B.base+cv['va']; CVSZ=cv['vs']; CVRAW=cv['raw']
def o_of(va):
    if CAVE<=va<CAVE+CVSZ: return CVRAW+(va-CAVE)
    return B.va2o(va)
# svobodnoe mesto v pechere (posle moih 318 bajt)
cur = CAVE
while d[o_of(cur)]!=0 or any(d[o_of(cur):o_of(cur)+64]): cur+=16
cur=(cur+15)&~15
print("svobodnaja pechera s %012x"%cur)

GLOBALS={0x180899dd8:0x18089c958, 0x1807e2998:0x1807e5518}
def locate_code(old_va):
    for nb in (48,40,32,24,16):
        pat,msk,_=make_sig(A,old_va,nb)
        if len(find(A,pat,msk))!=1: continue
        hs=find(B,pat,msk)
        if len(hs)==1: return hs[0]
    return None

# sajt: (staryj stab, dlina stabа, novyj sajt, skolko bajt zamenjaem, tip)
S=[(0x180113e60, 0x180e51a80, 0x73, 0x180114470, 90, 'jmp'),
   (0x180113f86, 0x180e51af8, 0x0b, 0x180114596,  6, 'call')]
OLDCAVE=A.base+A.getsec('.cave')['va']
for osite, ostub, slen, nsite, n, kind in S:
    blob=bytearray(da[A.va2o(ostub):A.va2o(ostub)+slen])
    nstub=cur
    # perenosim i pravim vneshnie ssylki
    fixes=[]
    for i in md.disasm(bytes(blob), ostub):
        off=i.address-ostub
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
        if m:
            dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
            t=i.address+i.size+dd
            nt=GLOBALS.get(t)
            assert nt, "neizvestnyj global %012x"%t
            e=i.encoding
            fixes.append((off+e.disp_offset, 4, nt, off+i.size, 'global'))
        elif i.mnemonic in ('jmp','call') and i.op_str.startswith('0x'):
            t=int(i.op_str,16)
            if OLDCAVE<=t<OLDCAVE+0x2000: continue
            if i.size==5:
                nt = (nsite+n) if t==(osite+n) else locate_code(t)
                assert nt, "ne najden kod %012x"%t
                fixes.append((off+1, 4, nt, off+i.size, 'kod'))
    for fo, fsz, tgt, endoff, what in fixes:
        struct.pack_into('<i', blob, fo, tgt-(nstub+endoff))
    o=o_of(nstub); assert all(x==0 for x in d[o:o+len(blob)])
    d[o:o+len(blob)]=blob
    # sajt -> tramplin
    op = b'\xe9' if kind=='jmp' else b'\xe8'
    patch = op+struct.pack('<i', nstub-(nsite+5))+b'\x90'*(n-5)
    so=B.va2o(nsite); d[so:so+n]=patch
    print("  sajt %012x -> stab %012x  (%d bajt stabа, zamena %d, %s, pravok %d)"
          %(nsite,nstub,slen,n,kind,len(fixes)))
    cur=(nstub+len(blob)+15)&~15
assert cur<CAVE+CVSZ
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
