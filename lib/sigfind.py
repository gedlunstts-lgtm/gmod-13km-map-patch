"""Poisk sajta po signature koda: opkody i registry sravnivaem,
   rip-smeshchenija i immediate - maskiruem. Ustojchivo k pereezdu dannyh."""
import sys
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from capstone import *

md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

def make_sig(pe, va, nbytes=40):
    """Vozvrashchaet (pattern, mask, dlina) - mask[i]=0 znachit bajt ignoriruem."""
    o=pe.va2o(va); d=bytes(pe.d)[o:o+nbytes+16]
    pat=bytearray(); msk=bytearray(); used=0
    for i in md.disasm(d, va):
        if used+i.size > nbytes: break
        b=bytearray(i.bytes); m=bytearray(b'\xff'*i.size)
        try: e=i.encoding
        except Exception: e=None
        if e:
            if e.disp_size: m[e.disp_offset:e.disp_offset+e.disp_size]=b'\x00'*e.disp_size
            if e.imm_size:  m[e.imm_offset:e.imm_offset+e.imm_size]  =b'\x00'*e.imm_size
        pat+=b; msk+=m; used+=i.size
    return bytes(pat), bytes(msk), used

def find(pe, pat, msk, secname='.text'):
    s=pe.getsec(secname); d=bytes(pe.d)
    lo=s['raw']; hi=lo+s['vs']; base=pe.base+s['va']
    n=len(pat); out=[]
    # bystryj predfiltr po pervomu nemaskirovannomu bajtu
    anchor=next((k for k in range(n) if msk[k]==0xff), 0)
    ab=pat[anchor]
    i=lo
    while True:
        i=d.find(bytes([ab]), i, hi)
        if i<0: break
        st=i-anchor
        if st>=lo and st+n<=hi:
            chunk=d[st:st+n]
            if all((chunk[k]&msk[k])==(pat[k]&msk[k]) for k in range(n)):
                out.append(base+(st-lo))
        i+=1
    return out
