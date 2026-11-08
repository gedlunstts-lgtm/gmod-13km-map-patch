"""Najti pravki fazy +-32k: kandidatnye funkcii v nojabrskom stoke
sverjaem s pre483 po maskirovannoj signature nachala funkcii."""
import sys, struct, bisect
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE
from sigport import mask_sig, find

COORD_F = {0x46800000, 0xc6800000, 0x47000000, 0xc7000000,
           0x47800000, 0xc7800000, 0x4b800000, 0xcb800000}
COORD_I = {16384, -16384, 32768, -32768, 0x3fff, 0x7fff, 14, 15, 0x4000, 0x8000,
           65536, 0x1000000, 0xfff, 0xffff, 12, 0x14}

def const_addrs(P, vals):
    """Adresa v .rdata/.data, gde lezhit odno iz 32-bitnyh znachenij."""
    out=set()
    for sec in ('.rdata','.data','_RDATA'):
        s=P.getsec(sec)
        if not s: continue
        d=bytes(P.d[s['raw']:s['raw']+s['rs']]); base=P.base+s['va']
        for v in vals:
            pat=struct.pack('<I',v); i=0
            while True:
                i=d.find(pat,i)
                if i<0: break
                if i%4==0: out.add(base+i)
                i+=1
    return out

def candidates(P):
    ca=const_addrs(P,COORD_F)
    fns=set()
    for f0,f1 in P.funcs:
        n=f1-f0
        if n<8 or n>0x3000: continue
        try: code=P.read(f0+P.base,n)
        except Exception: continue
        hit=False
        for ins in P.md.disasm(code,f0+P.base):
            e=ins.encoding
            if e.disp_size and 'rip' in ins.op_str:
                dd=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
                if ins.address+ins.size+dd in ca: hit=True; break
            if e.imm_size in (1,2,4):
                iv=int.from_bytes(ins.bytes[e.imm_offset:e.imm_offset+e.imm_size],'little',signed=True)
                if iv in COORD_I: hit=True; break
        if hit: fns.add(f0+P.base)
    return sorted(fns)

def shape(ins):
    b=bytearray(ins.bytes); e=ins.encoding
    for o,l in ((e.disp_offset,e.disp_size),(e.imm_offset,e.imm_size)):
        if l:
            for t in range(o,min(o+l,len(b))): b[t]=0
    return bytes(b)

def compare(NEW, OLD, fns, out=print):
    """Dlja kazhdoj kandidatnoj funkcii stoka ishchem ejo v pre483 i sravnivaem."""
    res=[]; nomatch=0
    for f0 in fns:
        i=bisect.bisect_right(NEW.fstarts,f0-NEW.base)-1
        s,e=NEW.funcs[i]; n=e-s
        if n>0x3000: continue
        nva=None
        for nb,pre in ((48,0),(96,0),(160,0)):
            r=mask_sig(NEW,f0,nb,pre)
            if not r: continue
            pat,msk,off,start=r
            if start!=f0: continue
            hits=find(OLD,pat,msk)
            if len(hits)==1: nva=hits[0]; break
        if nva is None: nomatch+=1; continue
        a=list(NEW.md.disasm(NEW.read(f0,n),f0))
        b=list(OLD.md.disasm(OLD.read(nva,n),nva))
        if len(a)!=len(b):
            res.append(('DLINA',f0,nva,len(a),len(b),None,None)); continue
        for x,y in zip(a,b):
            if x.bytes==y.bytes: continue
            if shape(x)==shape(y):
                # otlichaetsja tolko chislo: imm - nash patch, disp - pereezd adresov
                ex=x.encoding
                dl=[k for k in range(len(x.bytes)) if x.bytes[k]!=y.bytes[k]]
                inimm = ex.imm_size and all(ex.imm_offset<=k<ex.imm_offset+ex.imm_size for k in dl)
                if not inimm: continue
                res.append(('IMM',f0,nva,x.address,y.address,
                            '%s %s | %s'%(x.mnemonic,x.op_str,x.bytes.hex()),
                            '%s %s | %s'%(y.mnemonic,y.op_str,y.bytes.hex())))
            else:
                res.append(('OPKOD',f0,nva,x.address,y.address,
                            '%s %s | %s'%(x.mnemonic,x.op_str,x.bytes.hex()),
                            '%s %s | %s'%(y.mnemonic,y.op_str,y.bytes.hex())))
    out('funkcij ne sopostavleno: %d'%nomatch)
    return res
