"""v20 = v19 + ostavshiesja 70 pravok koordinatnoj fazy 483k.
Trampliny (7 sht) uzhe v v19. Zdes: 61 immediate, 13 rip->peshchera,
3 rip->maska, 6 polej v dannyh."""
import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from pediff import diff
from sigport import mask_sig, find
from portcoord3 import ins_at, find_in_sec, port_data
from portcoord4 import _narrow

U='/mnt/user-data/uploads/GarrysMod--bin--win64'
OLD=PE(U+'/engine.dll.pre483')      # 23.10, do 483k
PAT=PE('/home/claude/eng/engine.dll')# 23.10, posle 483k
STK=PE('/home/claude/fz2/engine_nov_stock.dll')  # chistyj nojabr - dlja poiska
V  =PE('/home/claude/fz2/engine_nov_v19.dll')    # nasha baza - v nejo pishem
d=bytearray(V.d)
cv=V.getsec('.cave'); CAVE=V.base+cv['va']; CVSZ=cv['vs']; CVRAW=cv['raw']
o_cave=lambda va: CVRAW+(va-CAVE)
ocave=[s for s in PAT.sec if s['name']=='.cave'][0]; OCAVE=PAT.base+ocave['va']

def tgt(ins):
    e=ins.encoding
    dd=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
    return ins.address+ins.size+dd

# --- 1) tablica konstant v svobodnoj chasti peshchery ---
TBL=0x180e53610
need={}   # staroe smeshchenie v peshchere -> (bajty,)
_,_,runs,_=diff(U+'/engine.dll.pre483','/home/claude/eng/engine.dll',show=False)
sites={}
for nm,va,oo,nn in runs:
    if nm!='.text': continue
    ia=ins_at(OLD,va)
    if ia is None: continue
    sites.setdefault(ia.address,(ia, ins_at(PAT,va)))
TRAMP={0x180114605,0x1801177f6,0x1802109a2,0x180210b28,0x180210caa,0x1802127ab,0x18021299e}
cave_sites=[]; rdata_sites=[]; imm_sites=[]
for va,(ia,ib) in sorted(sites.items()):
    if va in TRAMP: continue
    ra = tgt(ia) if (ia.encoding.disp_size and 'rip' in ia.op_str) else None
    rb = tgt(ib) if (ib.encoding.disp_size and 'rip' in ib.op_str) else None
    if ra is not None and rb is not None and ra!=rb:
        if OCAVE<=rb<OCAVE+ocave['vs']:
            off=rb-OCAVE
            oo2=PAT.va2o(rb); need[off]=bytes(PAT.d[oo2:oo2+4])
            cave_sites.append((va,ia,ib,off))
        else:
            oo2=PAT.va2o(rb); rdata_sites.append((va,ia,ib,bytes(PAT.d[oo2:oo2+4])))
    else:
        imm_sites.append((va,ia,ib))
# maski dlja rdata-sajtov tozhe polozhim v peshcheru
for va,ia,ib,bv in rdata_sites: need.setdefault(('m',bv), bv)

layout={}; cur=TBL
for k in sorted(need, key=lambda x: (isinstance(x,tuple), x)):
    layout[k]=cur; cur+=4
assert all(x==0 for x in d[o_cave(TBL):o_cave(cur)]), 'mesto pod tablicu zanjato'
for k,va in layout.items():
    d[o_cave(va):o_cave(va)+4]=need[k]
print('tablica konstant s %012x (%d zapisej):'%(TBL,len(layout)))
for k in sorted(layout, key=lambda x:layout[x]):
    b=need[k]
    print('   %012x  %s  float=%-14g  %s'%(layout[k],b.hex(),struct.unpack('<f',b)[0],
          ('cave+%03x'%k) if not isinstance(k,tuple) else 'maska'))

# --- 2) poisk sajta v nojabrskoj sborke ---
def locate(va):
    for nb,pre in ((40,3),(72,6),(120,10),(200,16),(320,24),(480,36)):
        r=mask_sig(OLD,va,nb,pre)
        if not r: continue
        pat,msk,off,start=r
        hits=find(STK,pat,msk)
        if len(hits)>1: hits=_narrow(OLD,STK,va,hits,off)
        if len(hits)==1: return hits[0]+off,None
    return None,'sovpadenij net ili mnogo'

ok=0; fails=[]
print('\n--- IMMEDIATE: %d ---'%len(imm_sites))
for va,ia,ib in imm_sites:
    nva,err=locate(va)
    if err: fails.append((va,err)); continue
    oo=V.va2o(nva); cur_b=bytes(d[oo:oo+ia.size])
    delta=[k for k in range(ia.size) if ia.bytes[k]!=ib.bytes[k]]
    e=ia.encoding
    fields=[]
    if e.imm_size:  fields.append((e.imm_offset, e.imm_size))
    if e.disp_size: fields.append((e.disp_offset, e.disp_size))
    # esli vsja raznica lezhit v odnom pole - perepisyvaem POLE celikom:
    # mezhdu stokom i +-32k konstanta uzhe mogla otlichatsja
    fld=None
    for fo,fs in fields:
        if delta and all(fo<=k<fo+fs for k in delta): fld=(fo,fs); break
    if fld:
        fo,fs=fld
        bad=[k for k in range(ia.size) if not (fo<=k<fo+fs) and cur_b[k]!=ia.bytes[k]]
        if bad: fails.append((va,'kontekst ne sovpal na %s (%s vs %s)'%(bad,cur_b.hex(),ia.bytes.hex()))); continue
        d[oo+fo:oo+fo+fs]=ib.bytes[fo:fo+fs]
    else:
        bad=[k for k in range(ia.size) if k not in delta and cur_b[k]!=ia.bytes[k]]
        if bad: fails.append((va,'kontekst ne sovpal na %s (%s vs %s)'%(bad,cur_b.hex(),ia.bytes.hex()))); continue
        for k in delta: d[oo+k]=ib.bytes[k]
    ok+=1
print('  perenseno %d/%d'%(ok,len(imm_sites)))

print('\n--- RIP -> peshchera: %d ---'%len(cave_sites))
ok2=0
for va,ia,ib,off in cave_sites:
    nva,err=locate(va)
    if err: fails.append((va,err)); continue
    oo=V.va2o(nva); cur_b=bytes(d[oo:oo+ia.size])
    do,ds=ia.encoding.disp_offset, ia.encoding.disp_size
    bad=[k for k in range(ia.size) if not (do<=k<do+ds) and cur_b[k]!=ia.bytes[k]]
    if bad: fails.append((va,'kontekst ne sovpal na %s'%bad)); continue
    disp=layout[off]-(nva+ia.size)
    d[oo+do:oo+do+ds]=struct.pack('<i',disp)
    ni=next(V.md.disasm(bytes(d[oo:oo+ia.size]),nva))
    print('  %012x -> %012x  %s %s  (cave+%03x)'%(va,nva,ni.mnemonic,ni.op_str,off))
    ok2+=1
print('  perenseno %d/%d'%(ok2,len(cave_sites)))

print('\n--- RIP -> maska: %d ---'%len(rdata_sites))
ok3=0
for va,ia,ib,bv in rdata_sites:
    nva,err=locate(va)
    if err: fails.append((va,err)); continue
    oo=V.va2o(nva); cur_b=bytes(d[oo:oo+ia.size])
    do,ds=ia.encoding.disp_offset, ia.encoding.disp_size
    bad=[k for k in range(ia.size) if not (do<=k<do+ds) and cur_b[k]!=ia.bytes[k]]
    if bad: fails.append((va,'kontekst ne sovpal na %s'%bad)); continue
    disp=layout[('m',bv)]-(nva+ia.size)
    d[oo+do:oo+do+ds]=struct.pack('<i',disp)
    ni=next(V.md.disasm(bytes(d[oo:oo+ia.size]),nva))
    print('  %012x -> %012x  %s %s  (maska %s)'%(va,nva,ni.mnemonic,ni.op_str,bv.hex()))
    ok3+=1
print('  perenseno %d/%d'%(ok3,len(rdata_sites)))

def refs_to(P, lo, hi):
    """Instrukcii v .text, ch'i rip-celi popadajut v [lo,hi)."""
    out=[]
    for f0,f1 in P.funcs:
        if f1-f0>0x4000: continue
        try: code=P.read(f0+P.base,f1-f0)
        except Exception: continue
        for ins in P.md.disasm(code,f0+P.base):
            e=ins.encoding
            if e.disp_size and 'rip' in ins.op_str:
                dd=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
                tt=ins.address+ins.size+dd
                if lo<=tt<hi: out.append((ins,tt))
    return out

def locate_data(base, span=0x40):
    """Najti adres bloka dannyh v novoj sborke po ssylkam iz koda."""
    cand={}
    for ins,tt in refs_to(OLD, base-span, base+span):
        nva,err=locate(ins.address)
        if err: continue
        try: ni=next(STK.md.disasm(STK.read(nva,16),nva))
        except StopIteration: continue
        e=ni.encoding
        if not e.disp_size or 'rip' not in ni.op_str: continue
        dd=int.from_bytes(ni.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
        nt=ni.address+ni.size+dd
        nb=nt-(tt-base)
        cand[nb]=cand.get(nb,0)+1
        if cand[nb]>=2: return nb,cand[nb],None
    if cand:
        best=max(cand,key=lambda k:cand[k])
        return (best,cand[best],None) if cand[best]>=2 else (None,0,'tolko %d podtverzhdenij'%cand[best])
    return None,0,'ssylok ne najdeno'

print('\n--- DANNYE ---')
datruns=[(nm,va,oo,nn) for nm,va,oo,nn in runs if nm!='.text']
bases=sorted({va-(va%4) for nm,va,oo,nn in datruns})
blk=min(bases)-(min(bases)%0x10)
nb,votes,err=locate_data(blk)
if err:
    fails.append((blk,'dannye: '+err)); print('  !! blok %012x: %s'%(blk,err))
else:
    print('  blok %012x -> %012x  (podtverzhdenij: %d)'%(blk,nb,votes))
    f=lambda b: struct.unpack('<f',b)[0]
    ok4=0
    for base in bases:
        nva=nb+(base-blk)
        oo2=V.va2o(nva); was=bytes(d[oo2:oo2+4])
        t=bytes(PAT.d[PAT.va2o(base):PAT.va2o(base)+4])
        d[oo2:oo2+4]=t
        print('    %012x -> %012x   %s (%g) => %s (%g)'%(base,nva,was.hex(),f(was),t.hex(),f(t)))
        ok4+=1

print('\nsboev: %d'%len(fails))
for va,why in fails: print('  !! %012x  %s'%(va,why))
if not fails:
    DST='/home/claude/fz2/engine_nov_v20.dll'
    open(DST,'wb').write(bytes(d))
    print('\n%s  MD5 %s'%(DST,hashlib.md5(bytes(d)).hexdigest()))
else:
    print('\nFAJL NE ZAPISAN')
