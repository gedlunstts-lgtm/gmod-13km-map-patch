"""Perenos koordinatnoj fazy 483k na novuju sborku. Odin fajl za vyzov."""
import sys, struct, hashlib, bisect
sys.path.insert(0,'/home/claude/tools')
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

def port_text(old_path, new_path, newstock_path, out_path, verbose=True):
    OLD=PE(old_path); PAT=PE(new_path); NEW=PE(newstock_path)
    d=bytearray(NEW.d)
    A,B,runs,newsec=diff(old_path,new_path,show=False)
    # gruppiruem otrezki po instrukcijam
    byins={}
    textruns=[r for r in runs if r[0]=='.text']
    other=[r for r in runs if r[0]!='.text']
    for name,va,o,n in textruns:
        ia=ins_at(OLD,va)
        assert ia is not None, '%012x ne v .pdata'%va
        byins.setdefault(ia.address,(ia, ins_at(PAT,va)))
    print('\nPRAVOK V .text: %d instrukcij'%len(byins))
    done=0; fails=[]
    for va,(ia,ib) in sorted(byins.items()):
        r=mask_sig(OLD,va)
        if not r: fails.append((va,'net signatury')); continue
        pat,msk,off,start=r
        hits=find(NEW,pat,msk)
        if len(hits)!=1: fails.append((va,'hits=%d'%len(hits))); continue
        nva=hits[0]+off
        o=NEW.va2o(nva)
        cur=bytes(d[o:o+ia.size])
        if cur!=ia.bytes:
            fails.append((va,'bajty ne te: %s vs %s'%(cur.hex(),ia.bytes.hex()))); continue
        d[o:o+ia.size]=ib.bytes
        done+=1
        if verbose:
            print('  %012x -> %012x  %s %s   =>   %s %s'%(
                va,nva,ia.mnemonic,ia.op_str,ib.mnemonic,ib.op_str))
    print('  perenseno %d/%d'%(done,len(byins)))
    for va,why in fails: print('  !! %012x  %s'%(va,why))
    return NEW,OLD,PAT,d,other,newsec,fails
