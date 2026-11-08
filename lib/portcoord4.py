"""Polnyj perenos koordinatnoj fazy odnogo fajla na novuju sborku.
   - tochechnye pravki immediate: pishem tolko otlichajushchiesja bajty
   - rip-otnositelnye ssylki v NOVYE sekcii: pereschityvaem smeshchenie
   - novye sekcii: dobavljaem i kopiruem soderzhimoe
   - polja v dannyh: ishchem po oknu s zamaskirovannym polem
"""
import sys, struct, hashlib, bisect
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE
from sigport import mask_sig, find
from pediff import diff
from portcoord3 import ins_at, find_in_sec, port_data
import addsec as A

def rip_target(ins):
    enc=ins.encoding
    if not enc.disp_size: return None
    if 'rip' not in ins.op_str: return None
    disp=int.from_bytes(ins.bytes[enc.disp_offset:enc.disp_offset+enc.disp_size],'little',signed=True)
    return ins.address+ins.size+disp, enc.disp_offset, enc.disp_size


def _fstart(P, va):
    rva=va-P.base; i=bisect.bisect_right(P.fstarts,rva)-1
    return P.funcs[i][0]+P.base

def _strs(P, fstart, n=0x400):
    out=[]
    try: code=P.read(fstart,n)
    except Exception: return out
    for ins in P.md.disasm(code, fstart):
        if ins.mnemonic=='lea' and 'rip' in ins.op_str:
            e=ins.encoding
            if not e.disp_size: continue
            disp=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
            t=ins.address+ins.size+disp
            try:
                o=P.va2o(t)
                if o is None: continue
                b=bytes(P.d[o:o+64]).split(b'\0')[0]
                if 2<len(b)<64 and all(32<=c<127 for c in b): out.append(b.decode())
            except Exception: pass
    return out

def _narrow(OLD, NEW, va, hits, off):
    """Razvodim odinakovye funkcii po strokam, na kotorye oni ssylajutsja."""
    want=_strs(OLD,_fstart(OLD,va))
    if not want: return hits
    keep=[h for h in hits if _strs(NEW,_fstart(NEW,h+off))==want]
    return keep if keep else hits

def run(old_path, new_path, stock_path, out_path, sec_chars=None, data_fields=True):
    OLD=PE(old_path); PAT=PE(new_path); STK=PE(stock_path)
    _,_,runs,newsec=diff(old_path,new_path,show=False)

    # --- 1) novye sekcii ---
    specs=[]; oldsecva={}
    for nm in newsec:
        s=[x for x in PAT.sec if x['name']==nm][0]
        payload=bytes(PAT.d[s['raw']:s['raw']+s['rs']])
        ch=(sec_chars or {}).get(nm, A.CODE if nm in ('.cave','.ctext') else A.DATA)
        specs.append((nm, s['vs'], ch, payload))
        oldsecva[nm]=PAT.base+s['va']
    if specs:
        d,placed=A.addsec(STK.d, specs)
        print('dobavleny sekcii:')
        for nm,(va,raw,rs) in placed.items():
            print('   %-7s va=%08x (%012x) raw=%d rs=%d   bylo u staroj %012x'%(
                nm,va,STK.base+va,raw,rs,oldsecva[nm]))
    else:
        d=bytearray(STK.d); placed={}
    newsecva={nm:STK.base+placed[nm][0] for nm in placed}
    # NEW nado perechitat posle addsec (smenilis sekcii/razmer) - ishchem po .text, on ne dvigalsja
    import tempfile, os
    tf=tempfile.NamedTemporaryFile(delete=False,suffix='.dll'); tf.write(bytes(d)); tf.close()
    NEW=PE(tf.name); os.unlink(tf.name)
    d=bytearray(NEW.d)

    def sec_of_abs(P, va, names):
        for nm in names:
            s=[x for x in P.sec if x['name']==nm]
            if not s: continue
            s=s[0]
            if P.base+s['va'] <= va < P.base+s['va']+max(s['vs'],s['rs']): return nm
        return None

    # --- 2) kod ---
    byins=sorted({ins_at(OLD,va).address for nm,va,o,n in runs
                  if nm=='.text' and ins_at(OLD,va)})
    datruns=[(nm,va,o,n) for nm,va,o,n in runs
             if not (nm=='.text' and ins_at(OLD,va))]
    print('\n--- KOD: %d instrukcij ---'%len(byins))
    ok=0; fails=[]
    for va in byins:
        ia=ins_at(OLD,va); ib=ins_at(PAT,va)
        nva=None; why='net signatury'
        for nb,pre in ((40,3),(72,6),(120,10),(200,16),(320,24),(480,36)):
            r=mask_sig(OLD,va,nb,pre)
            if not r: continue
            pat,msk,off,start=r
            hits=find(NEW,pat,msk)
            if len(hits)>1: hits=_narrow(OLD,NEW,va,hits,off)
            if len(hits)==1: nva=hits[0]+off; why=None; break
            why='sovpadenij %d (okno %d/%d)'%(len(hits),nb,pre)
        if nva is None: fails.append((va,why)); continue
        o=NEW.va2o(nva)
        cur=bytes(d[o:o+ia.size])
        rt=rip_target(ib)
        tgtsec=sec_of_abs(PAT, rt[0], list(newsec)) if rt else None
        if tgtsec:
            # pereschitat disp na novuju sekciju
            offin=rt[0]-oldsecva[tgtsec]
            newabs=newsecva[tgtsec]+offin
            disp=newabs-(nva+ia.size)
            do,ds=rt[1],rt[2]
            bad=[k for k in range(ia.size) if not (do<=k<do+ds) and cur[k]!=ia.bytes[k]]
            if bad: fails.append((va,'kontekst ne sovpal na %s'%bad)); continue
            d[o+do:o+do+ds]=struct.pack('<i',disp)
            ni=next(NEW.md.disasm(bytes(d[o:o+ia.size]),nva))
            print('  %012x -> %012x  %s %s  =>  %s %s   [%s+%#x]'%(
                va,nva,ia.mnemonic,ia.op_str,ni.mnemonic,ni.op_str,tgtsec,offin))
            ok+=1; continue
        delta=[k for k in range(ia.size) if ia.bytes[k]!=ib.bytes[k]]
        bad=[k for k in range(ia.size) if k not in delta and cur[k]!=ia.bytes[k]]
        if bad: fails.append((va,'kontekst ne sovpal na %s'%bad)); continue
        for k in delta: d[o+k]=ib.bytes[k]
        ni=next(NEW.md.disasm(bytes(d[o:o+ia.size]),nva))
        print('  %012x -> %012x  %-28s =>  %s %s'%(
            va,nva,'%s %s'%(ia.mnemonic,ia.op_str),ni.mnemonic,ni.op_str))
        ok+=1
    print('  kod: %d/%d'%(ok,len(byins)))
    for va,why in fails: print('  !! %012x %s'%(va,why))

    # --- 3) dannye ---
    if data_fields and datruns:
        print('\n--- DANNYE: %d polej ---'%len(datruns))
        f=lambda b: struct.unpack('<f',b)[0] if len(b)==4 else None
        for nm,va,o,n in datruns:
            r,err=port_data(NEW,OLD,PAT,d,nm,va)
            if err: fails.append((va,'dannye: '+err)); print('  !! %s %012x %s'%(nm,va,err)); continue
            nva,was,tgt,w=r
            print('  %s %012x -> %012x (okno %d)  %s (%g) => %s (%g)'%(
                nm,va,nva,w,was.hex(),f(was),tgt.hex(),f(tgt)))
    if out_path:
        open(out_path,'wb').write(bytes(d))
        print('\n%s  MD5 %s  %d bajt'%(out_path,hashlib.md5(bytes(d)).hexdigest(),len(d)))
    return d,fails
