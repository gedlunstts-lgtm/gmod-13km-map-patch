import sys, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
exe = sys.argv[1]
P = PE(exe)
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
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
# ищем: shl rX, 5 / imul rX, 0x20  (шаг 32) и shl rX,4 (16) рядом с lea на .data
susp=[]
for (s,e) in P.funcs:
    ins=func_ins(s,e)
    for i,x in enumerate(ins):
        sh=None
        if x.mnemonic=='shl' and x.op_str.endswith(', 5'): sh=32
        if x.mnemonic=='imul' and x.op_str.endswith(', 0x20'): sh=32
        if sh:
            for y in ins[i:i+6]:
                if 'rip' in y.op_str and y.mnemonic=='lea':
                    m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', y.op_str)
                    if m:
                        dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                        t=y.address+y.size+dd
                        sec=P.sec_of_rva(t-P.base)
                        if sec and sec['name'] in ('.data','.bigarr'):
                            susp.append((P.base+s, x.address, x.mnemonic+' '+x.op_str, t, sec['name']))
                            break
print(f'--- {exe}: мест с шагом 32 по массиву в .data ---')
seen=set()
for f,a,t,tgt,sec in susp:
    if (a,tgt) in seen: continue
    seen.add((a,tgt))
    print(f'  func {f:012x}  {a:012x}  {t:<18} -> {tgt:012x} [{sec}]')
if not susp: print('  нет')
