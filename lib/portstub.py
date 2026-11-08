"""Perenos zaglushek v novyh sekcijah na druguju sborku.
Vsjo, chto zaglushka trogaet snaruzhi, pereadresuetsja po signature
iz NEPATCHENNOGO starogo fajla."""
import sys, struct, bisect, hashlib, tempfile, os
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE
from sigport import mask_sig, find
from pediff import diff
import addsec as A

WINS=((48,0),(80,0),(128,0),(200,0),(320,0))

def fstart(P, va):
    i=bisect.bisect_right(P.fstarts,va-P.base)-1
    if i<0: return None
    s,e=P.funcs[i]
    return s+P.base if s<=va-P.base<e else None

def locate_fn(OLD, NEW, va):
    """Nachalo funkcii -> novyj adres."""
    for nb,pre in WINS:
        r=mask_sig(OLD,va,nb,pre)
        if not r: continue
        pat,msk,off,start=r
        if start!=va: continue
        h=find(NEW,pat,msk)
        if len(h)==1: return h[0]
    return None

def _window(ins, lo, hi):
    """Maskirovannoe okno iz instrukcij ins[lo:hi]."""
    pat=bytearray(); msk=bytearray()
    for x in ins[lo:hi]:
        pat+=x.bytes; msk+=b'\xff'*x.size
        e=x.encoding
        for o,l in ((e.disp_offset,e.disp_size),(e.imm_offset,e.imm_size)):
            if l:
                b0=len(pat)-x.size+o
                for t in range(l): msk[b0+t]=0
    return bytes(pat), bytes(msk)

def locate_code(OLD, NEW, va, span=0x200):
    """Ljuboj adres v .text novoj sborki.

    Snachala okno VPERJOD ot va: bajty v samoj celi v oboih fajlah
    originalnye, a vot pered nej mesta mozhet ne hvatit - naprimer kogda
    cel v odnoj instrukcii ot nachala funkcii. Potom okno nazad, potom
    oba vmeste, i tolko potom nachalo funkcii so smeshcheniem.
    """
    # --- 1) vperjod ot va
    try:
        fwd=list(OLD.md.disasm(OLD.read(va, span), va))
    except Exception:
        fwd=[]
    for cnt in (6,10,16,24,36,56):
        if cnt>len(fwd): break
        pat,msk=_window(fwd,0,cnt)
        if not any(msk): continue
        h=find(NEW,pat,msk)
        if len(h)==1: return h[0]
    # --- 2) nazad do va, i 3) oba vmeste
    f=fstart(OLD,va)
    if f is not None:
        try:
            back=list(OLD.md.disasm(OLD.read(f, va-f+span), f))
        except Exception:
            back=[]
        k=next((i for i,x in enumerate(back) if x.address==va), None)
        if k:
            for cnt in (6,10,16,24,36,56,80):
                a=max(0,k-cnt)
                pat,msk=_window(back,a,k)
                if not any(msk): continue
                h=find(NEW,pat,msk)
                if len(h)==1: return h[0]+len(pat)
            for cnt in (10,20,36,56,80):
                a=max(0,k-cnt); b=min(len(back),k+cnt)
                pat,msk=_window(back,a,b)
                if not any(msk): continue
                h=find(NEW,pat,msk)
                if len(h)==1: return h[0]+(back[k].address-back[a].address)
        # --- 4) nachalo funkcii plus smeshchenie
        nf=locate_fn(OLD,NEW,f)
        if nf is not None: return nf+(va-f)
    return None

def refs_to(P, lo, hi, skip_secs=()):
    out=[]
    skip=[]
    for nm in skip_secs:
        s=P.getsec(nm)
        if s: skip.append((P.base+s['va'],P.base+s['va']+max(s['vs'],s['rs'])))
    for f0,f1 in P.funcs:
        n=f1-f0
        if n<8 or n>0x4000: continue
        va0=f0+P.base
        if any(a<=va0<b for a,b in skip): continue
        try: code=P.read(va0,n)
        except Exception: continue
        for ins in P.md.disasm(code,va0):
            e=ins.encoding
            if e.disp_size and 'rip' in ins.op_str:
                dd=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
                t=ins.address+ins.size+dd
                if lo<=t<hi: out.append((ins,t))
    return out

def locate_data(OLD, NEW, va, span=0x40, need=2):
    """Adres v .data/.rdata -> novyj, po ssylkam iz koda (nuzhno >=need golosov)."""
    cand={}
    for ins,t in refs_to(OLD, va-span, va+span, skip_secs=('.ctext','.cave')):
        n=locate_code(OLD,NEW,ins.address)
        if n is None: continue
        try: ni=next(NEW.md.disasm(NEW.read(n,16),n))
        except StopIteration: continue
        e=ni.encoding
        if not e.disp_size or 'rip' not in ni.op_str: continue
        dd=int.from_bytes(ni.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
        nt=ni.address+ni.size+dd
        nb=nt-(t-va)
        cand[nb]=cand.get(nb,0)+1
        if cand[nb]>=need: return nb,cand[nb]
    if cand:
        b=max(cand,key=lambda k:cand[k])
        return (b,cand[b]) if cand[b]>=need else (None,cand[b])
    return None,0


def reachable(P, entries, lo, hi, limit=0x4000):
    """Rekursivnyj obhod koda ot tochek vhoda. Vozvrashchaet {adres: ins}."""
    seen={}; work=list(entries)
    BR={'je','jne','jz','jnz','jl','jle','jg','jge','jb','jbe','ja','jae','js','jns',
        'jo','jno','jp','jnp','jecxz','jrcxz'}
    while work:
        va=work.pop()
        while lo<=va<hi and va not in seen:
            try: ins=next(P.md.disasm(P.read(va,16),va))
            except StopIteration: break
            seen[va]=ins
            op=ins.op_str
            if ins.mnemonic in BR and op.startswith('0x'):
                t=int(op,16)
                if lo<=t<hi: work.append(t)
            elif ins.mnemonic=='call' and op.startswith('0x'):
                t=int(op,16)
                if lo<=t<hi: work.append(t)
            elif ins.mnemonic=='jmp':
                if op.startswith('0x'):
                    t=int(op,16)
                    if lo<=t<hi: va=t; continue
                break
            elif ins.mnemonic in ('ret','retf','ud2'):
                break
            va+=ins.size
    return seen


def _sec_chars_of(P, name):
    """Characteristics sekcii iz gotovogo fajla-obrazca."""
    optsz,=struct.unpack_from('<H',P.d,P.pe+20)
    off=P.pe+24+optsz
    for i in range(len(P.sec)):
        nm=bytes(P.d[off+i*40:off+i*40+8]).split(b'\0')[0].decode()
        if nm==name:
            ch,=struct.unpack_from('<I',P.d,off+i*40+36)
            return ch
    return A.CODE

def port_file(old_unp, old_pat, stock, out_path, secnames=('.ctext','.cdata'), verbose=True):
    OLD=PE(old_unp); PAT=PE(old_pat); STK=PE(stock)
    _,_,runs,newsec=diff(old_unp,old_pat,show=False)
    newsec=[n for n in secnames if n in newsec]
    specs=[]; oldva={}
    for nm in newsec:
        s=[x for x in PAT.sec if x['name']==nm][0]
        # Prava berjom iz obrazca, a ne ugadyvaem po imeni: sekcija, v
        # kotoruju zaglushka pishet, objazana byt zapisyvaemoj, i po
        # nazvaniju eto ne vidno.
        specs.append((nm, s['vs'], _sec_chars_of(PAT, nm),
                      bytes(PAT.d[s['raw']:s['raw']+s['rs']])))
        oldva[nm]=PAT.base+s['va']
    d,placed=A.addsec(STK.d, specs)
    tf=tempfile.NamedTemporaryFile(delete=False,suffix='.dll'); tf.write(bytes(d)); tf.close()
    NEW=PE(tf.name); os.unlink(tf.name); d=bytearray(NEW.d)
    newva={nm:NEW.base+placed[nm][0] for nm in placed}
    deltas={nm:newva[nm]-oldva[nm] for nm in newsec}
    if verbose:
        for nm in newsec:
            print('  %-7s %012x -> %012x   sdvig %+#x'%(nm,oldva[nm],newva[nm],deltas[nm]))
    assert len(set(deltas.values()))==1, 'sekcii sdvinulis po-raznomu, vnutrennie ssylki slomajutsja'
    D=next(iter(deltas.values()))

    inside=lambda v: any(oldva[n]<=v<oldva[n]+ [x['vs'] for x in PAT.sec if x['name']==n][0] for n in newsec)
    # Kotoraja iz novyh sekcij derzhit kod? Ta, kuda prygaet .text.
    import stubs as _st0
    _ents=_st0.entries(PAT, list(newsec))
    _code_sec=None
    for _nm in newsec:
        _s=[x for x in PAT.sec if x['name']==_nm][0]
        _lo=PAT.base+_s['va']; _hi=_lo+max(_s['vs'],_s['rs'])
        if any(_lo<=e<_hi for e in _ents): _code_sec=_nm; break
    if _code_sec is None: _code_sec=newsec[0]
    ct=[x for x in PAT.sec if x['name']==_code_sec][0]
    blob=bytes(PAT.d[ct['raw']:ct['raw']+ct['rs']])
    nz=max(i for i,x in enumerate(blob) if x)
    CT_OLD=PAT.base+ct['va']; CT_NEW=newva[_code_sec]
    o_new=lambda va: NEW.va2o(va)

    # tochki vhoda: kuda prygaet .text, plus vsjo dostizhimoe ottuda
    import stubs as _st
    ents=sorted(_st.entries(PAT, list(newsec)))
    code=reachable(PAT, ents, CT_OLD, CT_OLD+ct['vs'])
    if verbose: print('  tochek vhoda %d, dostignuto instrukcij %d'%(len(ents),len(code)))
    fixed=0; fails=[]
    for _va in sorted(code):
        ins=code[_va]
        e=ins.encoding
        t=None; fo=fs=None; rel=False
        if e.disp_size and 'rip' in ins.op_str:
            dd=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
            t=ins.address+ins.size+dd; fo,fs=e.disp_offset,e.disp_size
        elif ins.mnemonic in ('jmp','call') and ins.op_str.startswith('0x'):
            t=int(ins.op_str,16); fo,fs=e.imm_offset,e.imm_size; rel=True
        if t is None or inside(t): continue
        sec=PAT.sec_of_rva(t-PAT.base); snm=sec['name'] if sec else None
        if snm=='.text':
            f=fstart(OLD,t)
            nt = locate_fn(OLD,NEW,t) if f==t else locate_code(OLD,NEW,t)
            how='funkcija' if f==t else 'kod'
        elif snm in ('.data','.rdata','_RDATA'):
            nt,votes=locate_data(OLD,NEW,t); how='dannye(%d)'%votes
            if nt is None:
                sh=neighbour_shift(OLD,NEW,t)
                if sh is not None: nt=t+sh; how='po sosedjam %+#x'%sh
        else:
            fails.append((ins.address,'cel v %s'%snm)); continue
        if nt is None:
            fails.append((ins.address,'%s: ne nashjol %012x'%(how,t))); continue
        nva=ins.address+D
        o=o_new(nva)
        newdisp=nt-(nva+ins.size)
        d[o+fo:o+fo+fs]=struct.pack('<i',newdisp)
        if verbose:
            print('    %012x %-30s %012x -> %012x  [%s]'%(
                nva,'%s %s'%(ins.mnemonic,ins.op_str),t,nt,how))
        fixed+=1
    return NEW,OLD,PAT,d,newva,oldva,D,fixed,fails,runs

def apply_tramps(OLD, PAT, NEW, d, runs, newsec, D, verbose=True):
    """Tramplinу v .text: najti sajt, proverit stokovye bajty, napisat jmp na novyj stab."""
    rng=[]
    for nm in newsec:
        s=[x for x in PAT.sec if x['name']==nm][0]
        rng.append((PAT.base+s['va'], PAT.base+s['va']+s['vs']))
    ins_at_pat={}
    sites=set()
    for nm,va,o,n in runs:
        if nm!='.text': continue
        f=fstart(PAT,va)
        # nachalo tramplina: ishchem e9 ne dalshe 16 bajt nazad
        for back in range(0,17):
            cand=va-back
            try: x=next(PAT.md.disasm(PAT.read(cand,16),cand))
            except StopIteration: continue
            # i jmp, i call: v dvizhke est zaglushka, v kotoruju vhodjat call-om
            if x.mnemonic in ('jmp','call') and x.op_str.startswith('0x'):
                t=int(x.op_str,16)
                if any(a<=t<b for a,b in rng) and cand<=va<cand+x.size:
                    sites.add((cand,t,x.mnemonic)); break
    ok=0; fails=[]; covered=[]
    for site,stub,kind in sorted(sites):
        # dlina vytesnennogo kuska = do tochki vozvrata zaglushki
        import stubs as _st2
        wl=_st2.walk(PAT, stub, list(newsec), limit=0x400)
        back=None
        for x in wl:
            if x.mnemonic=='jmp' and x.op_str.startswith('0x'):
                t2=int(x.op_str,16)
                if not any(a<=t2<b for a,b in rng): back=t2
        if back is None:
            # net vozvrata (naprimer stab konchaetsja ret) - berjom po instrukcijam
            L=0
            for x in OLD.md.disasm(OLD.read(site,32),site):
                L+=x.size
                if L>=5: break
        else:
            L=back-site
            # Granica shirokaja naroch: nastojashchaja proverka nizhe -
            # bajty v najdennom meste sverjajutsja s nepatchennym fajlom.
            # Odna iz zaglushek dvizhka vytesnjaet celyj cikl na 90 bajt.
            if not (5<=L<=512):
                fails.append((site,'podozritelnaja dlina %d (vozvrat %012x)'%(L,back))); continue
        nsite=locate_code(OLD,NEW,site)
        if nsite is None: fails.append((site,'sajt ne najden')); continue
        o=NEW.va2o(nsite)
        cur=bytes(d[o:o+L]); want=OLD.read(site,L)
        if cur!=want:
            fails.append((site,'bajty ne stokovye: %s vs %s'%(cur.hex(),want.hex()))); continue
        tgt=stub+D
        op=b'\xe8' if kind=='call' else b'\xe9'
        d[o:o+L]=op+struct.pack('<i',tgt-(nsite+5))+b'\x90'*(L-5)
        covered.append((site,L))
        if verbose: print('    tramplin %-4s %012x -> %012x  (%d bajt, nops %d)'%(kind,nsite,tgt,L,L-5))
        ok+=1
    return ok,fails,covered

_REFS_CACHE={}
def _sec_refs(OLD, secname, lo, hi):
    key=(id(OLD),secname)
    if key in _REFS_CACHE: return _REFS_CACHE[key]
    seen={}
    for f0,f1 in OLD.funcs:
        try: code=OLD.read(f0+OLD.base,f1-f0)
        except Exception: continue
        for ins in OLD.md.disasm(code,f0+OLD.base):
            e=ins.encoding
            if e.disp_size and 'rip' in ins.op_str:
                dd=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
                t=ins.address+ins.size+dd
                if lo<=t<hi: seen[t]=seen.get(t,0)+1
    o=sorted(x for x in seen if seen[x]>=3)
    _REFS_CACHE[key]=o
    return o

def neighbour_shift(OLD, NEW, va, each=3):
    """Sdvig adresa po BLIZHAJSHIM sosedjam s dvuh storon.
       Sekcija celikom mozhet sdvigatsja neodnorodno (.data: nachalo 0,
       .bss-hvost +0x60), poetomu obshchij sdvig ne godites."""
    s=OLD.sec_of_rva(va-OLD.base)
    if not s: return None
    lo=OLD.base+s['va']; hi=lo+max(s['vs'],s['rs'])
    o=_sec_refs(OLD,s['name'],lo,hi)
    if len(o)<2: return None
    import bisect as _b
    i=_b.bisect_left(o,va)
    pick=o[max(0,i-each):i]+o[i:i+each]
    got=[]
    for x in pick:
        n,v=locate_data(OLD,NEW,x,span=0x20,need=2)
        if n is not None: got.append(n-x)
    if len(got)>=2 and len(set(got))==1: return got[0]
    return None
