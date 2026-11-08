"""Perenos pravok v tablice ukazatelej (.rdata): nahodim tablicu v novoj
sborke po ejo zhe soderzhimomu - kazhdyj ukazatel razreshaem po signature."""
import sys, struct
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE
from portstub import locate_fn, locate_code, fstart

def find_bytes_masked(P, secname, pat, msk):
    s=P.getsec(secname)
    d=bytes(P.d[s['raw']:s['raw']+s['rs']]); base=P.base+s['va']
    n=len(pat); hits=[]
    anchor=next((i for i in range(n) if msk[i]), None)
    if anchor is None: return []
    run=anchor
    while run<n and msk[run]: run+=1
    needle=pat[anchor:run]
    i=0
    while True:
        i=d.find(needle,i)
        if i<0: break
        st=i-anchor
        if st>=0 and st+n<=len(d) and st%8==0:
            seg=d[st:st+n]
            if all((not msk[k]) or seg[k]==pat[k] for k in range(n)):
                hits.append(base+st)
        i+=1
    return hits

def port_table(OLD, PAT, NEW, d, slots, margin=6, verbose=True):
    """slots: [(va_sloty, novoe_znachenie)] - adresa v .rdata starogo fajla."""
    lo=min(v for v,_ in slots)-margin*8
    hi=max(v for v,_ in slots)+margin*8+8
    nslot=(hi-lo)//8
    pat=bytearray(); msk=bytearray()
    resolved={}
    for k in range(nslot):
        va=lo+k*8
        try: old,=struct.unpack_from('<Q',bytes(OLD.d),OLD.va2o(va))
        except Exception: old=None
        nv=None
        if old and OLD.base<=old<OLD.base+0x10000000:
            s=OLD.sec_of_rva(old-OLD.base)
            if s and s['name']=='.text':
                nv = locate_fn(OLD,NEW,old) if fstart(OLD,old)==old else locate_code(OLD,NEW,old)
        if nv is None:
            pat+=b'\0'*8; msk+=b'\0'*8
        else:
            pat+=struct.pack('<Q',nv); msk+=b'\xff'*8
            resolved[k]=nv
    if verbose:
        print('  slotov v okne %d, razreshjono ukazatelej %d'%(nslot,len(resolved)))
    hits=find_bytes_masked(NEW,'.rdata',bytes(pat),bytes(msk))
    if len(hits)!=1:
        return None,'tablica: sovpadenij %d'%len(hits)
    nbase=hits[0]
    ok=0
    for va,newval in slots:
        k=(va-lo)//8
        nva=nbase+k*8
        o=NEW.va2o(nva)
        was,=struct.unpack_from('<Q',bytes(d),o)
        struct.pack_into('<Q',d,o,newval)
        if verbose:
            print('    %012x -> %012x   %016x => %016x'%(va,nva,was,newval))
        ok+=1
    return (nbase,ok),None
