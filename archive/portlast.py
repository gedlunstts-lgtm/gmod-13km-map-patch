import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from sigfind import make_sig, find
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
FZ=PE('/home/claude/fz/engine_fz.dll'); V4=PE('/home/claude/fz/engine_v04.dll')
B=PE('/home/claude/fz2/engine_nov_v11.dll'); d=bytearray(B.d)
fz=bytes(FZ.d); v4=bytes(V4.d)
def shape(i):
    b=bytearray(i.bytes); m=bytearray(b'\xff'*i.size)
    try: e=i.encoding
    except Exception: e=None
    if e:
        if e.disp_size: m[e.disp_offset:e.disp_offset+e.disp_size]=b'\x00'*e.disp_size
        if e.imm_size:  m[e.imm_offset:e.imm_offset+e.imm_size]=b'\x00'*e.imm_size
    return bytes(bytearray(x&y for x,y in zip(b,m)))
# --- dva sajta cherez vyravnivanie ot nachala funkcii
for va,size,nf in [(0x1800f1147,4,0x1800f1418),(0x1800f1ef7,4,0x1800f2238)]:
    f=FZ.func_of(va)
    ia=list(md.disasm(fz[FZ.va2o(f[0]):FZ.va2o(f[0])+(f[1]-f[0])],f[0]))
    ib=list(md.disasm(bytes(B.d)[B.va2o(nf):B.va2o(nf)+(f[1]-f[0])+400],nf))
    p=q=0; found=None
    while p<len(ia) and q<len(ib):
        if ia[p].address==va: found=ib[q].address; break
        if shape(ia[p])==shape(ib[q]): p+=1; q+=1; continue
        ok=False
        for w in range(1,20):
            for dp in range(0,w+1):
                dq=w-dp
                if p+dp<len(ia) and q+dq<len(ib) and shape(ia[p+dp])==shape(ib[q+dq]):
                    p+=dp; q+=dq; ok=True; break
            if ok: break
        if not ok: break
        p+=1; q+=1
    if found is None: print("  %012x ne vyrovnjalsja"%va); continue
    o=B.va2o(found); cur=bytes(d[o:o+size]); src=fz[FZ.va2o(va):FZ.va2o(va)+size]
    if cur!=src: print("  %012x -> %012x bajty ne sovpali (%s vs %s)"%(va,found,cur.hex(),src.hex())); continue
    d[o:o+size]=v4[V4.va2o(va):V4.va2o(va)+size]
    print("  %012x -> %012x  perenjeseno"%(va,found))
# --- dva tramplina v pecheru
cv=B.getsec('.cave'); CAVE=B.base+cv['va']; CVSZ=cv['vs']; CVRAW=cv['raw']
def o_of(va): return CVRAW+(va-CAVE) if CAVE<=va<CAVE+CVSZ else B.va2o(va)
cur=CAVE
while any(d[o_of(cur):o_of(cur)+64]): cur+=16
cur=(cur+15)&~15
print("pechera svobodna s %012x"%cur)
OLDCAVE=V4.base+V4.getsec('.cave')['va']
import re
def locate_code(old_va):
    for nb in (48,40,32,24,16):
        pat,msk,_=make_sig(FZ,old_va,nb)
        if len(find(FZ,pat,msk))!=1: continue
        hs=find(B,pat,msk)
        if len(hs)==1: return hs[0]
    return None
S=[(0x180113e60,0x180e51a80,0x73,0x180114470,90,'jmp'),
   (0x180113f86,0x180e51af8,0x0b,0x180114596, 6,'call')]
for osite,ostub,slen,nsite,n,kind in S:
    blob=bytearray(v4[V4.va2o(ostub):V4.va2o(ostub)+slen])
    nstub=cur; fixes=[]
    for i in md.disasm(bytes(blob),ostub):
        off=i.address-ostub
        if i.mnemonic in ('jmp','call') and i.op_str.startswith('0x'):
            t=int(i.op_str,16)
            if OLDCAVE<=t<OLDCAVE+0x2000: continue
            if i.size==5:
                nt=(nsite+n) if t==(osite+n) else locate_code(t)
                assert nt,"ne najden kod %012x"%t
                fixes.append((off+1,nt,off+i.size))
    for fo,tgt,endoff in fixes:
        struct.pack_into('<i',blob,fo,tgt-(nstub+endoff))
    o=o_of(nstub); assert all(x==0 for x in d[o:o+len(blob)])
    d[o:o+len(blob)]=blob
    op=b'\xe9' if kind=='jmp' else b'\xe8'
    so=B.va2o(nsite); d[so:so+n]=op+struct.pack('<i',nstub-(nsite+5))+b'\x90'*(n-5)
    print("  tramplin %012x -> %012x (%d bajt, pravok %d)"%(nsite,nstub,len(blob),len(fixes)))
    cur=(nstub+len(blob)+15)&~15
DST='/home/claude/fz2/engine_nov_v12.dll'
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
