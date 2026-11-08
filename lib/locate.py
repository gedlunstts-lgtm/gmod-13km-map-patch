"""Poisk sajtov patcha po signaturam, bez zhjostkih adresov.
Proverjaetsja na starom stoke, gde pravilnyj otvet izvesten."""
import sys, re, struct
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE
from capstone import *

CBITVEC_STRINGS = [b'CBitVec invalid set bitNum %i',
                   b'CBitVec invalid clear bitNum %i',
                   b'CBitVec invalid IsBitSet bitNum %i',
                   b'CBitVec invalid TestAndSet bitNum %i',
                   b'CBitVec invalid get uint32 bitNum %i',
                   b'CBitVec invalid set newVal bitNum %i']

def find_strings(p):
    """VA kazhdoj stroki oshibki - jakor, nezavisimyj ot versii."""
    d=bytes(p.d); out={}
    for s in CBITVEC_STRINGS:
        for m in re.finditer(re.escape(s), d):
            va=p.o2va(m.start())
            if va: out.setdefault(s.decode(),[]).append(va)
    return out

def find_bitvec_checks(p):
    """Ishchem shablon:  movzx r32, word [BASE+D] ; cmp r32,r32 ; jl OK ; <err>
       D opredeljaem sami - eto smeshchenie m_numBits, a ne vshityj 0x578."""
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    d=bytes(p.d); hits=[]
    for s,e in p.funcs:
        va=p.base+s; o=p.va2o(va)
        if o is None: continue
        ins=list(md.disasm(d[o:o+min(e-s,0x20000)],va))
        for k in range(len(ins)-2):
            a,b,c = ins[k],ins[k+1],ins[k+2]
            if a.mnemonic!='movzx' or 'word ptr' not in a.op_str: continue
            m=re.match(r'(\w+), word ptr \[(\w+) \+ (0x[0-9a-f]+)\]$', a.op_str)
            if not m: continue
            dstreg, basereg, disp = m.group(1), m.group(2), int(m.group(3),16)
            if b.mnemonic!='cmp': continue
            mb=re.match(r'(\w+), '+dstreg+'$', b.op_str)
            if not mb: continue
            if c.mnemonic!='jl': continue
            ok=int(c.op_str,16); err=c.address+c.size
            # posle err-vetki dolzhna idti zagruzka stroki CBitVec
            tail=ins[k+3:k+8]
            hits.append(dict(site=a.address, idxreg=mb.group(1), base=basereg,
                             numbits_off=disp, ok=ok, err=err,
                             movzx=a.bytes.hex(), cmpb=b.bytes.hex(),
                             span=c.address+c.size-a.address,
                             tail=[(x.mnemonic,x.op_str) for x in tail]))
    return hits
