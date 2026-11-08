import sys, struct, hashlib, bisect
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from sigfind import make_sig, find
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
FZ=PE('/home/claude/fz/engine_fz.dll'); V4=PE('/home/claude/fz/engine_v04.dll')
SRC='/home/claude/fz2/engine_nov_v02.dll'; DST='/home/claude/fz2/engine_nov_v11.dll'
B=PE(SRC); d=bytearray(B.d)
fz=bytes(FZ.d); v4=bytes(V4.d)

# --- nastojashchie granicy instrukcij v FZ
bounds={}   # va -> size
for s,e in FZ.funcs:
    va=FZ.base+s; o=FZ.va2o(va)
    if o is None: continue
    for i in md.disasm(fz[o:o+min(e-s,0x20000)],va):
        bounds[i.address]=i.size
t=FZ.getsec('.text'); TLO=t['raw']; THI=TLO+t['vs']; TVA=FZ.base+t['va']
for st in range(0,THI-TLO,2048):
    for i in md.disasm(fz[TLO+st:TLO+st+2100], TVA+st):
        bounds.setdefault(i.address,i.size)
keys=sorted(bounds)
print("granic instrukcij:",len(keys))

runs=[]; i=TLO
while i<THI:
    if fz[i]!=v4[i]:
        j=i
        while j<THI and fz[j]!=v4[j]: j+=1
        runs.append((FZ.base+FZ.o2r(i), FZ.base+FZ.o2r(j-1)+1)); i=j
    else: i+=1
edits=[]
for lo,hi in runs:
    k=bisect.bisect_right(keys,lo)-1
    if k<0: print("  net granicy dlja %012x"%lo); continue
    st=keys[k]
    end=st
    while end<hi and end in bounds: end+=bounds[end]
    if end<hi: end=hi
    edits.append((st,end-st))
edits.sort(); merged=[]
for st,sz in edits:
    if merged and st<=merged[-1][0]+merged[-1][1]:
        e=max(merged[-1][0]+merged[-1][1],st+sz); merged[-1]=(merged[-1][0],e-merged[-1][0])
    else: merged.append((st,sz))
print("pravok posle vyravnivanija: %d"%len(merged))

def locate(va,size):
    f=FZ.func_of(va); starts=[va]
    if f:
        o=FZ.va2o(f[0]); prev=[]
        for ins in md.disasm(fz[o:o+(f[1]-f[0])],f[0]):
            if ins.address>=va: break
            prev.append(ins.address)
        starts += prev[-20:][::-1]
    for st in starts:
        n=(va-st)+size
        if n<6 or n>260: continue
        pat,msk,used=make_sig(FZ,st,n)
        if used!=n: continue
        if len(find(FZ,pat,msk))!=1: continue
        hs=find(B,pat,msk)
        if len(hs)==1: return hs[0]+(va-st)
    # vtoraja popytka: jakor PRODOLZhAETSJa za sajt
    for extra in (16,24,32,48,64,96):
        for st in starts[:8]:
            n=(va-st)+size+extra
            if n<8 or n>300: continue
            pat,msk,used=make_sig(FZ,st,n)
            if used<(va-st)+size: continue
            if len(find(FZ,pat,msk))!=1: continue
            hs=find(B,pat,msk)
            if len(hs)==1: return hs[0]+(va-st)
    return None
SKIP={0x180113e60,0x180113f86,0x180113f31}
ok=0; miss=[]
for va,size in merged:
    if va in SKIP: continue
    nva=locate(va,size)
    if nva is None: miss.append((va,size,'jakor')); continue
    o=B.va2o(nva)
    if bytes(d[o:o+size])!=fz[FZ.va2o(va):FZ.va2o(va)+size]:
        miss.append((va,size,'bajty ne sovpali')); continue
    d[o:o+size]=v4[V4.va2o(va):V4.va2o(va)+size]; ok+=1
print("perenjeseno %d, ne najdeno %d"%(ok,len(miss)))
for va,size,why in miss: print("   %012x (%d b)  %s"%(va,size,why))
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
