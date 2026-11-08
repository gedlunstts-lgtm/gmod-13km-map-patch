import sys
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
from capstone.x86 import *
import re
P = PE('/home/claude/fz/engine_fz.dll')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
TARGETS = {0x1807e2998:'worldbrushdata_ptr'}
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
hits={}
for (s,e) in P.funcs:
    for ins in func_ins(s,e):
        if 'rip' in ins.op_str:
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
            if m:
                d=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                t=ins.address+ins.size+d
                if t in TARGETS:
                    hits.setdefault(P.base+s,[]).append((ins.address, ins.mnemonic+' '+ins.op_str))
print('functions referencing worldbrushdata ptr:', len(hits))
for f in sorted(hits):
    print(f'{f:012x}  n={len(hits[f])}')
