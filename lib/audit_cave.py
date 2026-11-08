import sys, struct
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE

def entries(P):
    # Sekcija s zaglushkami zovjotsja po-raznomu: .cave v dvizhke,
    # .ctext v graficheskih fajlah.
    c=None
    for _nm in ('.cave','.ctext'):
        c=P.getsec(_nm)
        if c: break
    if not c: return {},None
    CAVE=P.base+c['va']
    t=P.getsec('.text'); td=bytes(P.d[t['raw']:t['raw']+t['rs']]); TVA=P.base+t['va']
    ents={}
    for i in range(len(td)-5):
        if td[i] in (0xe9,0xe8):
            dd,=struct.unpack_from('<i',td,i+1)
            tgt=TVA+i+5+dd
            if CAVE<=tgt<CAVE+c['vs']:
                ents.setdefault(tgt,[]).append((TVA+i,'call' if td[i]==0xe8 else 'jmp'))
    return ents,(CAVE,c['vs'])

def walk(P, ent, cave, limit=0x200):
    """Projti stab do terminatora. Vozvrashchaet (instrukcii, verdikt)."""
    CAVE,SZ=cave
    out=[]; va=ent
    while va-ent < limit:
        code=P.read(va,16)
        try: ins=next(P.md.disasm(code,va))
        except StopIteration:
            return out,'NERASPOZNANNYJ BAJT %012x'%va
        out.append(ins)
        if ins.mnemonic=='ret': return out,'ret'
        if ins.mnemonic=='jmp' and ins.op_str.startswith('0x'):
            t=int(ins.op_str,16)
            if CAVE<=t<CAVE+SZ: va=t; continue        # vnutrennij perehod
            s=P.sec_of_rva(t-P.base)
            return out,('vozvrat v %s %012x'%(s['name'],t) if s and s['name']=='.text'
                        else 'VOZVRAT NE V .text: %012x'%t)
        if ins.mnemonic=='jmp': return out,'jmp po registru'
        va+=ins.size
        if not any(P.read(va,8)):
            return out,'UPAL V NULI na %012x - NET VOZVRATA'%va
        # prishli na chuzhuju tochku vhoda?
        return_check=va
    return out,'ne nashjol terminator za %d bajt'%limit

if __name__=='__main__':
    for p in sys.argv[1:]:
        P=PE(p); ents,cave=entries(P)
        print('=== %s : %d tochek vhoda ==='%(p.split('/')[-1],len(ents)))
        allents=set(ents)
        for ent in sorted(ents):
            ins,verd=walk(P,ent,cave)
            # proverim, ne zashli li my v druguju tochku vhoda
            spill=[x.address for x in ins if x.address!=ent and x.address in allents]
            flag='  <<< NALOZHENIE na %012x'%spill[0] if spill else ''
            bad = ('NET VOZVRATA' in verd or 'NE V .text' in verd or 'ne nashjol' in verd
                   or 'NERASPOZNANNYJ' in verd or spill)
            print('  %012x <- %-28s  %3d instr  %s%s  %s'%(
                ent, ', '.join('%012x %s'%x for x in ents[ent]), len(ins), verd, flag,
                'PLOHO' if bad else 'ok'))
        print()
