"""Sopostavlenie funkcij po ssylkam na stroki - strokovye literaly mezhdu
sborkami ne menjajutsja, poetomu dajut tochnyj jakor, a ne dogadku."""
import sys, re
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE

ASCII=re.compile(rb'[\x20-\x7e]{10,}')

def strings(P):
    """{tekst: va} tolko dlja unikalnyh v predelah fajla."""
    out={}
    for sec in ('.rdata','_RDATA','.data'):
        s=P.getsec(sec)
        if not s: continue
        d=bytes(P.d[s['raw']:s['raw']+s['rs']]); base=P.base+s['va']
        for m in ASCII.finditer(d):
            t=m.group()
            if d[m.end():m.end()+1] not in (b'\0',b'\n',b'\r'): continue
            if t in out: out[t]=None
            else: out[t]=base+m.start()
    return {k:v for k,v in out.items() if v}

def ripmap(P, wanted):
    """{va_stroki: [(fn_start, ins_addr)]} - kto ssylaetsja na eti adresa."""
    res={}
    for f0,f1 in P.funcs:
        n=f1-f0
        if n<8 or n>0x6000: continue
        try: code=P.read(f0+P.base,n)
        except Exception: continue
        for ins in P.md.disasm(code,f0+P.base):
            e=ins.encoding
            if not e.disp_size or 'rip' not in ins.op_str: continue
            dd=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
            t=ins.address+ins.size+dd
            if t in wanted: res.setdefault(t,[]).append((f0+P.base,ins.address))
    return res

def shape(ins):
    b=bytearray(ins.bytes); e=ins.encoding
    for o,l in ((e.disp_offset,e.disp_size),(e.imm_offset,e.imm_size)):
        if l:
            for t in range(o,min(o+l,len(b))): b[t]=0
    return bytes(b)

def pairs(A, B, filt=None):
    sa=strings(A); sb=strings(B)
    common=[t for t in sa if t in sb and (filt is None or filt(t))]
    ra=ripmap(A,{sa[t] for t in common})
    rb=ripmap(B,{sb[t] for t in common})
    out={}
    for t in common:
        la=ra.get(sa[t]); lb=rb.get(sb[t])
        if not la or not lb: continue
        fa={x[0] for x in la}; fb={x[0] for x in lb}
        if len(fa)!=1 or len(fb)!=1: continue
        out[(fa.pop(),fb.pop())]=t
    return out
