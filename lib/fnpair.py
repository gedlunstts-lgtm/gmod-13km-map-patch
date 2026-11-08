"""Sopostavlenie funkcij mezhdu sborkami po maskirovannoj forme koda.
Dva prohoda i nichego lishnego v pamjati."""
import sys, hashlib
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE

def shape(ins):
    b=bytearray(ins.bytes); e=ins.encoding
    for o,l in ((e.disp_offset,e.disp_size),(e.imm_offset,e.imm_size)):
        if l:
            for t in range(o,min(o+l,len(b))): b[t]=0
    return bytes(b)

def hashes(P, k=24, maxlen=0x3000):
    """{hash: (va, dlina)} - tolko odnoznachnye."""
    m={}
    for f0,f1 in P.funcs:
        n=f1-f0
        if n<16 or n>maxlen: continue
        try: code=P.read(f0+P.base,n)
        except Exception: continue
        h=hashlib.blake2b(digest_size=12); cnt=0
        for ins in P.md.disasm(code,f0+P.base):
            if cnt<k: h.update(shape(ins))
            cnt+=1
        if cnt<6: continue
        h.update(bytes([min(cnt,255)]))
        key=h.digest()
        if key in m: m[key]=None
        else: m[key]=(f0+P.base,n,cnt)
    return {k2:v for k2,v in m.items() if v}

def scan(a_path, b_path, k=24, out=print):
    A=PE(a_path); ha=hashes(A,k); out('A: odnoznachnyh funkcij %d'%len(ha))
    B=PE(b_path); hb=hashes(B,k); out('B: odnoznachnyh funkcij %d'%len(hb))
    common=set(ha)&set(hb)
    out('sopostavleno %d'%len(common))
    found=[]
    for key in common:
        ava,an,acnt=ha[key]; bva,bn,bcnt=hb[key]
        if acnt!=bcnt: continue
        ia=list(A.md.disasm(A.read(ava,an),ava))
        ib=list(B.md.disasm(B.read(bva,bn),bva))
        if len(ia)!=len(ib): continue
        for x,y in zip(ia,ib):
            if x.bytes==y.bytes: continue
            kind='CHISLO' if shape(x)==shape(y) else 'OPKOD'
            found.append((kind,ava,x.address,'%s %s'%(x.mnemonic,x.op_str),x.bytes.hex(),
                          bva,y.address,'%s %s'%(y.mnemonic,y.op_str),y.bytes.hex()))
    return found
