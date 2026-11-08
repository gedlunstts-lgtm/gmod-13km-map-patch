"""Razbor zaglushek v novyh sekcijah: vse ssylki s klassifikaciej."""
import sys, struct
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from pe import PE

def entries(P, secnames):
    """{adres_vhoda: [(sajt, 'jmp'/'call')]} - perehody iz .text v novye sekcii."""
    rng=[]
    for nm in secnames:
        s=P.getsec(nm)
        if s: rng.append((P.base+s['va'], P.base+s['va']+max(s['vs'],s['rs'])))
    t=P.getsec('.text'); td=bytes(P.d[t['raw']:t['raw']+t['rs']]); TVA=P.base+t['va']
    ents={}
    for i in range(len(td)-5):
        if td[i] in (0xe9,0xe8):
            dd,=struct.unpack_from('<i',td,i+1)
            tg=TVA+i+5+dd
            if any(a<=tg<b for a,b in rng):
                ents.setdefault(tg,[]).append((TVA+i,'call' if td[i]==0xe8 else 'jmp'))
    return ents

def walk(P, ent, secnames, limit=0x400):
    """Instrukcii zaglushki do terminatora."""
    rng=[]
    for nm in secnames:
        s=P.getsec(nm)
        if s: rng.append((P.base+s['va'], P.base+s['va']+max(s['vs'],s['rs'])))
    inside=lambda v: any(a<=v<b for a,b in rng)
    out=[]; va=ent; seen=set()
    while va-ent<limit and va not in seen:
        seen.add(va)
        try: ins=next(P.md.disasm(P.read(va,16),va))
        except StopIteration: break
        out.append(ins)
        if ins.mnemonic=='ret': break
        if ins.mnemonic=='jmp':
            if ins.op_str.startswith('0x'):
                t=int(ins.op_str,16)
                if inside(t): va=t; continue
            break
        va+=ins.size
    return out

def refs(P, ins_list, secnames):
    """[(ins, kind, target)] kind: 'vnutri' | 'text' | '<sekcija>'"""
    rng=[]
    for nm in secnames:
        s=P.getsec(nm)
        if s: rng.append((nm,P.base+s['va'], P.base+s['va']+max(s['vs'],s['rs'])))
    def where(v):
        for nm,a,b in rng:
            if a<=v<b: return 'vnutri:'+nm
        s=P.sec_of_rva(v-P.base)
        return s['name'] if s else 'VNE'
    out=[]
    for ins in ins_list:
        e=ins.encoding
        if e.disp_size and 'rip' in ins.op_str:
            dd=int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset+e.disp_size],'little',signed=True)
            t=ins.address+ins.size+dd
            out.append((ins,'rip',where(t),t,e.disp_offset,e.disp_size))
        elif ins.mnemonic in ('jmp','call') and ins.op_str.startswith('0x'):
            t=int(ins.op_str,16)
            out.append((ins,'rel',where(t),t,e.imm_offset,e.imm_size))
    return out
