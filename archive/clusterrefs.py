import sys, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
P = PE('/home/claude/vbsp/vbsp_v02.exe')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
RANGES=[(0x140048000,0x14004b200),(0x14007a000,0x14007e000),(0x140066000,0x140067400)]
def func_ins(s,e):
    va=P.base+s; o=P.va2o(va)
    if o is None: return []
    buf=bytes(P.d[o:o+(e-s)]); out=[]; cur=0
    while cur<len(buf):
        got=False
        for ins in md.disasm(buf[cur:], va+cur):
            got=True; out.append(ins); cur=ins.address-va+ins.size
        if not got: cur+=1
    return out
agg={}
for (s,e) in P.funcs:
    fv=P.base+s
    if not any(lo<=fv<hi for lo,hi in RANGES): continue
    for ins in func_ins(s,e):
        if 'rip' in ins.op_str:
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
            if m:
                d=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                t=ins.address+ins.size+d
                sec=P.sec_of_rva(t-P.base)
                if sec and sec['name'] in ('.data','.bigarr'):
                    agg.setdefault(t,set()).add((fv,ins.address,ins.mnemonic+' '+ins.op_str.split('rip')[0].strip()))
for t in sorted(agg):
    sec=P.sec_of_rva(t-P.base)['name']
    fns=sorted(set(f for f,_,_ in agg[t]))
    print(f'{t:012x} [{sec:<7}] refs={len(agg[t]):<3} funcs={" ".join(f"{f:x}" for f in fns)}')
