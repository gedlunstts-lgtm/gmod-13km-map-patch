"""Perenos tochechnyh pravok mezhdu sborkami po maskirovannoj signature.
Signaturu berjom VSEGDA iz NEPATCHENNOGO starogo fajla."""
import sys, struct
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE
from capstone import *

def mask_sig(P, va, nbytes=40, pre=3):
    """Vozvrashchaet (pattern, mask, off_in_pattern) dlja okna, nachinajushchegosja
       na granice instrukcii <= va, dlinoj >= nbytes. disp/imm zamaskirovany."""
    import bisect
    rva=va-P.base
    i=bisect.bisect_right(P.fstarts,rva)-1
    s,e=P.funcs[i]
    code=P.read(s+P.base, e-s)
    ins=list(P.md.disasm(code, s+P.base))
    k=None
    for idx,x in enumerate(ins):
        if x.address<=va<x.address+x.size: k=idx; break
    if k is None: return None
    # okno: 3 instrukcii do i vperjod poka ne nabereem nbytes
    a=max(0,k-pre)
    b=k
    while b<len(ins) and ins[b].address+ins[b].size-ins[a].address < nbytes: b+=1
    b=min(b+1,len(ins))
    start=ins[a].address
    pat=bytearray(); msk=bytearray()
    for x in ins[a:b]:
        pat+=x.bytes; msk+=b'\xff'*x.size
        enc=x.encoding
        for o,l in ((enc.disp_offset,enc.disp_size),(enc.imm_offset,enc.imm_size)):
            if l:
                base=len(pat)-x.size+o
                for t in range(l): msk[base+t]=0
    return bytes(pat), bytes(msk), va-start, start

def _anchor(pat, msk, minlen=4):
    """Samaja dlinnaja nepreryvnaja nemaskirovannaja cepochka."""
    best=(0,0); i=0; n=len(msk)
    while i<n:
        if msk[i]:
            j=i
            while j<n and msk[j]: j+=1
            if j-i>best[1]: best=(i,j-i)
            i=j
        else: i+=1
    return best

def find(P, pat, msk, sec='.text'):
    t=P.getsec(sec)
    d=bytes(P.d[t['raw']:t['raw']+t['rs']])
    n=len(pat); hits=[]
    ao,al=_anchor(pat,msk)
    if al==0: return []
    needle=pat[ao:ao+al]
    i=0
    while True:
        i=d.find(needle,i)
        if i<0: break
        st=i-ao
        if st>=0 and st+n<=len(d):
            seg=d[st:st+n]
            ok=True
            for k in range(n):
                if msk[k] and seg[k]!=pat[k]: ok=False; break
            if ok: hits.append(P.base+t['va']+st)
        i+=1
    return hits
