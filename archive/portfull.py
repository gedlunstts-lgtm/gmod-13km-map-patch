import sys, struct, hashlib, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from sigfind import make_sig, find
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
FZ=PE('/home/claude/fz/engine_fz.dll')
V4=PE('/home/claude/fz/engine_v04.dll')
SRC='/home/claude/fz2/engine_nov_v02.dll'   # bazа: moi leaffaces+CBitVec+SURFEDGES+VIS
DST='/home/claude/fz2/engine_nov_v10.dll'
B=PE(SRC); d=bytearray(B.d)
fz=bytes(FZ.d); v4=bytes(V4.d); db=bytes(B.d)

# --- 1. instrukcii, izmenjonnye mezhdu FZ i V4 v .text
t=FZ.getsec('.text'); TLO=t['raw']; THI=TLO+t['vs']
runs=[]; i=TLO
while i<THI:
    if fz[i]!=v4[i]:
        j=i
        while j<THI and fz[j]!=v4[j]: j+=1
        runs.append((i,j)); i=j
    else: i+=1
# rasshirjaem kazhdyj otrezok do granic instrukcij v FZ
edits=[]
for lo,hi in runs:
    va=FZ.base+FZ.o2r(lo)
    st=None
    for back in range(0,20):
        s=va-back; o=FZ.va2o(s)
        ins=list(md.disasm(fz[o:o+40],s))
        if ins and ins[0].address<=va<ins[0].address+ins[0].size:
            st=ins[0].address; break
    if st is None: print("  ne vyrovnjal %012x"%va); continue
    # dlina: pokryt ves otrezok celymi instrukcijami
    end=FZ.base+FZ.o2r(hi-1)+1
    o=FZ.va2o(st); cur=st; size=0
    for ins in md.disasm(fz[o:o+64],st):
        size+=ins.size; cur=ins.address+ins.size
        if cur>=end: break
    edits.append((st,size))
# sklеим perekryvajushchiesja
edits.sort(); merged=[]
for st,sz in edits:
    if merged and st<=merged[-1][0]+merged[-1][1]:
        e=max(merged[-1][0]+merged[-1][1], st+sz); merged[-1]=(merged[-1][0], e-merged[-1][0])
    else: merged.append((st,sz))
print("pravok v .text: %d (otrezkov bylo %d)"%(len(merged),len(runs)))

# --- 2. perenos
def locate(va, size):
    """jakor: neskolko instrukcij FZ, zakanchivajushchihsja NA sajte"""
    f=FZ.func_of(va)
    starts=[va]
    if f:
        o=FZ.va2o(f[0]); prev=[]
        for ins in md.disasm(fz[o:o+(f[1]-f[0])],f[0]):
            if ins.address>=va: break
            prev.append(ins.address)
        starts += prev[-14:][::-1]
    for st in starts:
        n=(va-st)+size
        if n<6 or n>220: continue
        pat,msk,used=make_sig(FZ,st,n)
        if used!=n: continue
        if len(find(FZ,pat,msk))!=1: continue
        hs=find(B,pat,msk)
        if len(hs)==1: return hs[0]+(va-st)
    return None
ok=0; miss=[]
for va,size in merged:
    nva=locate(va,size)
    if nva is None: miss.append((va,size)); continue
    o=B.va2o(nva)
    # sverim, chto tam lezhit to zhe, chto v FZ
    if bytes(d[o:o+size])!=fz[FZ.va2o(va):FZ.va2o(va)+size]:
        miss.append((va,size)); continue
    d[o:o+size]=v4[V4.va2o(va):V4.va2o(va)+size]
    ok+=1
print("perenjeseno: %d, ne najdeno: %d"%(ok,len(miss)))
for va,size in miss: print("   NE NAJDEN %012x (%d bajt)"%(va,size))
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
