import sys, re, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from sigfind import make_sig, find
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
A=PE('/home/claude/fz/engine_v04.dll')
SRC='/home/claude/fz2/engine_nov_v02.dll'      # bazа: BEZ moih pravok rjober/indeksov
DST='/home/claude/fz2/engine_nov_v07.dll'
B=PE(SRC); d=bytearray(B.d); da=bytes(A.d); db=bytes(B.d)
def shape(i):
    b=bytearray(i.bytes); m=bytearray(b'\xff'*i.size)
    try: e=i.encoding
    except Exception: e=None
    if e:
        if e.disp_size: m[e.disp_offset:e.disp_offset+e.disp_size]=b'\x00'*e.disp_size
        if e.imm_size:  m[e.imm_offset:e.imm_offset+e.imm_size]=b'\x00'*e.imm_size
    return bytes(bytearray(x&y for x,y in zip(b,m)))
# --- 1. vse funkcii novogo dvizhka, gde est obrashchenie k [X+0x108] 16 bitami
FUNCS=set()
for s,e in B.funcs:
    va=B.base+s; o=B.va2o(va)
    if o is None: continue
    ins=list(md.disasm(db[o:o+min(e-s,0x20000)],va))
    for k,i in enumerate(ins):
        m=re.match(r'^(\w+), qword ptr \[(\w+) \+ 0x108\]$', i.op_str)
        if not m or i.mnemonic!='mov': continue
        reg=m.group(1)
        for j in ins[k+1:k+8]:
            t=j.mnemonic+' '+j.op_str
            if reg in j.op_str and (('word ptr' in t and 'dword' not in t) or '*2' in t):
                FUNCS.add(va); break
print("funkcij s 16-bitnym dostupom k [X+0x108]:",len(FUNCS))
# --- 2. dlja kazhdoj najdjom paru v starom i perenesjom vse izmenenija shiriny
def is_width_change(a,b):
    ta,tb=a.mnemonic+' '+a.op_str, b.mnemonic+' '+b.op_str
    if ('dword ptr' in ta and 'word ptr' in tb and 'dword' not in tb): return True
    if ('*4' in ta and '*2' in tb): return True
    if a.mnemonic=='lea' and b.mnemonic=='lea':
        ma=re.search(r'\+ (0x[0-9a-f]+|\d+)\]$',ta); mb=re.search(r'\+ (0x[0-9a-f]+|\d+)\]$',tb)
        if ma and mb:
            va_=int(ma.group(1),0); vb_=int(mb.group(1),0)
            if va_==vb_*2: return True
    if a.mnemonic=='shl' and b.mnemonic=='add' and b.op_str.split(',')[0].strip()==b.op_str.split(',')[1].strip(): return True
    if a.mnemonic=='add' and b.mnemonic=='add':
        ma=re.search(r', (\d+)$',ta); mb=re.search(r', (\d+)$',tb)
        if ma and mb and int(ma.group(1))==int(mb.group(1))*2: return True
    return False
total=0; skipped=[]
for nf in sorted(FUNCS):
    pat,msk,_=make_sig(B,nf,64)
    hs=find(A,pat,msk)
    if len(hs)!=1: skipped.append((nf,'ne privjazana')); continue
    af=hs[0]
    fa=A.func_of(af); fb=B.func_of(nf)
    ia=list(md.disasm(da[A.va2o(fa[0]):A.va2o(fa[0])+(fa[1]-fa[0])],fa[0]))
    ib=list(md.disasm(db[B.va2o(fb[0]):B.va2o(fb[0])+(fb[1]-fb[0])],fb[0]))
    p=q=0; n=0
    while p<len(ia) and q<len(ib):
        if shape(ia[p])==shape(ib[q]): p+=1; q+=1; continue
        a,b=ia[p],ib[q]
        if is_width_change(a,b) and a.size<=b.size:
            o=B.va2o(b.address)
            d[o:o+b.size]=a.bytes+b'\x90'*(b.size-a.size)
            n+=1; total+=1
        done=False
        for w in range(1,25):
            for dp in range(0,w+1):
                dq=w-dp
                if p+dp<len(ia) and q+dq<len(ib) and shape(ia[p+dp])==shape(ib[q+dq]):
                    p+=dp; q+=dq; done=True; break
            if done: break
        if not done: break
        p+=1; q+=1
    if n: print("  %012x <- %012x  pravok %d"%(nf,af,n))
print("\nvsego pravok shiriny:",total)
if skipped:
    print("ne privjazany (%d):"%len(skipped))
    for x,why in skipped[:10]: print("   %012x %s"%(x,why))
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
