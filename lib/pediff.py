"""Diff dvuh PE odnoj sborki: pravki po sekcijam + novye sekcii (nashi peshchery)."""
import sys, struct, hashlib, datetime
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE

def info(p):
    P=PE(p); ts,=struct.unpack_from('<I',P.d,P.pe+8)
    return P, ts

def diff(a_path, b_path, show=True):
    A,tsa=info(a_path); B,tsb=info(b_path)
    na=a_path.split('/')[-1]; nb=b_path.split('/')[-1]
    print('== %s  ->  %s'%(na,nb))
    print('   razmer %d -> %d   link %08x / %08x  %s'%(
        len(A.d),len(B.d),tsa,tsb,'SBORKA ODNA' if tsa==tsb else 'SBORKI RAZNYE!'))
    secA={s['name']:s for s in A.sec}; secB={s['name']:s for s in B.sec}
    print('   sekcii A:',[s['name'] for s in A.sec])
    print('   sekcii B:',[s['name'] for s in B.sec])
    out=[]
    for name,sa in secA.items():
        sb=secB.get(name)
        if sb is None: print('   !! sekcija %s propala'%name); continue
        n=min(sa['rs'],sb['rs'])
        da=A.d[sa['raw']:sa['raw']+n]; db=B.d[sb['raw']:sb['raw']+n]
        if da==db: continue
        runs=[];i=0
        while i<n:
            if da[i]!=db[i]:
                j=i
                while j<n and da[j]!=db[j]: j+=1
                runs.append((i,j-i)); i=j
            else: i+=1
        print('   [%s] otrezkov %d, bajt %d'%(name,len(runs),sum(r[1] for r in runs)))
        for off,ln in runs:
            va=A.base+sa['va']+off
            out.append((name,va,bytes(da[off:off+ln]),bytes(db[off:off+ln])))
    newsec=[n for n in secB if n not in secA]
    for name in newsec:
        s=secB[name]
        blob=bytes(B.d[s['raw']:s['raw']+s['rs']])
        nz=sum(1 for x in blob if x)
        print('   NOVAJA sekcija %s  va=%08x vs=%d rs=%d  nenulevyh bajt %d'%(
            name,s['va'],s['vs'],s['rs'],nz))
    return A,B,out,newsec

if __name__=='__main__':
    diff(sys.argv[1], sys.argv[2])
