import sys, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
P = PE('/home/claude/vbsp/vvis_v04.exe')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
WANT=[int(x,16) for x in sys.argv[1:]]
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
res={w:[] for w in WANT}
for (s,e) in P.funcs:
    ins=func_ins(s,e)
    for i,x in enumerate(ins):
        if 'rip' in x.op_str:
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', x.op_str)
            if m:
                d=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                t=x.address+x.size+d
                if t in res:
                    ctx=ins[max(0,i-4):i+5]
                    res[t].append((P.base+s, x.address, [(c.address,c.mnemonic+' '+c.op_str) for c in ctx]))
for w in WANT:
    print('='*78)
    print(f'=== {w:x}   refs={len(res[w])}')
    for fn,addr,ctx in res[w]:
        print(f'  --- func {fn:012x}')
        for a,t in ctx:
            mark='>>' if a==addr else '  '
            print(f'   {mark} {a:012x}  {t}')
