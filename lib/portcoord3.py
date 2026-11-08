"""Perenos koordinatnoj fazy 483k na novuju sborku.
Pravim TOLKO te bajty vnutri instrukcii, kotorye otlichajutsja mezhdu
staroj i patchennoj versiej. Ostalnye bajty v novoj sborke proverjaem.
Dlja dannyh - poisk okna s zamaskirovannym izmenjaemym polem."""
import sys, struct, hashlib, bisect
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE
from sigport import mask_sig, find
from pediff import diff

def ins_at(P, va):
    rva=va-P.base; i=bisect.bisect_right(P.fstarts,rva)-1
    if i<0: return None
    s,e=P.funcs[i]
    if not (s<=rva<e): return None
    for ins in P.md.disasm(P.read(s+P.base,e-s), s+P.base):
        if ins.address<=va<ins.address+ins.size: return ins
    return None

def find_in_sec(P, secname, pat, msk):
    s=P.getsec(secname)
    d=bytes(P.d[s['raw']:s['raw']+s['rs']])
    n=len(pat); hits=[]
    anchor=next(i for i in range(n) if msk[i])
    ab=bytes([pat[anchor]])
    i=0
    while True:
        i=d.find(ab,i)
        if i<0: break
        st=i-anchor
        if st>=0 and st+n<=len(d):
            seg=d[st:st+n]
            if all((seg[k]&msk[k])==(pat[k]&msk[k]) for k in range(n)):
                hits.append(P.base+s['va']+st)
        i+=1
    return hits

def port(old_path, new_path, stock_path, out_path, data_width=4):
    OLD=PE(old_path); PAT=PE(new_path); NEW=PE(stock_path)
    d=bytearray(NEW.d)
    A,B,runs,newsec=diff(old_path,new_path,show=False)
    byins={}; datruns=[]
    for name,va,o,n in runs:
        ia=ins_at(OLD,va) if name=='.text' else None
        if ia is not None: byins.setdefault(ia.address, ia.address)
        else: datruns.append((name,va,o,n))
    print('\n--- KOD: %d instrukcij ---'%len(byins))
    ok=0; fails=[]
    for va in sorted(byins):
        ia=ins_at(OLD,va); ib=ins_at(PAT,va)
        delta=[k for k in range(ia.size) if ia.bytes[k]!=ib.bytes[k]]
        r=mask_sig(OLD,va)
        if not r: fails.append((va,'net signatury')); continue
        pat,msk,off,start=r
        hits=find(NEW,pat,msk)
        if len(hits)!=1: fails.append((va,'sovpadenij %d'%len(hits))); continue
        nva=hits[0]+off
        o=NEW.va2o(nva); cur=bytes(d[o:o+ia.size])
        bad=[k for k in range(ia.size) if k not in delta and cur[k]!=ia.bytes[k]]
        if bad: fails.append((va,'nesovpadenie vne polja na %s'%bad)); continue
        for k in delta: d[o+k]=ib.bytes[k]
        new=bytes(d[o:o+ia.size])
        ni=next(NEW.md.disasm(new,nva))
        print('  %012x -> %012x  %-30s => %s %s'%(
            va,nva,'%s %s'%(ia.mnemonic,ia.op_str),ni.mnemonic,ni.op_str))
        ok+=1
    print('  kod: %d/%d'%(ok,len(byins)))
    for va,why in fails: print('  !! %012x %s'%(va,why))
    return NEW,OLD,PAT,d,datruns,newsec,fails

def port_data(NEW, OLD, PAT, d, name, va, width=4, win=72):
    """Pole shirinoj width, soderzhashchee va. Ishchem okno s zamaskirovannym polem.
       Qwordy, pohozhie na ukazateli v obraz, i dlinnye nuli tozhe maskiruem -
       oni ezhjat ot sborki k sborke."""
    s=OLD.getsec(name)
    base=va - ((va - (OLD.base+s['va'])) % width)
    bo=OLD.va2o(base)
    lo=OLD.base; hi=OLD.base+0x10000000
    for w in (16, 32, 48, 72, 128):
        half=(w-width)//2
        half-=half % 8
        st=bo-half
        pat=bytes(OLD.d[st:st+w]); msk=bytearray(b'\xff'*w)
        for k in range(half,half+width): msk[k]=0
        # maskiruem qwordy-ukazateli
        q0=(st//8)*8
        for q in range(st-(st%8), st+w, 8):
            if q<st: continue
            chunk=bytes(OLD.d[q:q+8])
            if len(chunk)<8: break
            v=int.from_bytes(chunk,'little')
            if lo<=v<hi:
                for k in range(q-st, min(q-st+8,w)): msk[k]=0
        if not any(msk): continue
        hits=find_in_sec(NEW,name,pat,bytes(msk))
        if len(hits)==1:
            nbase=hits[0]+half
            no=NEW.va2o(nbase)
            was=bytes(d[no:no+width]); tgt=bytes(PAT.d[bo:bo+width])
            d[no:no+width]=tgt
            return (nbase,was,tgt,w),None
    return None,'okno ne odnoznachno (proboval 16..128)'
