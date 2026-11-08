import sys, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
P = PE('/home/claude/vbsp/vbsp_v02.exe')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
targets={}
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
for (s,e) in P.funcs:
    for ins in func_ins(s,e):
        if 'rip' in ins.op_str:
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
            if m:
                d=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                t=ins.address+ins.size+d
                sec=P.sec_of_rva(t-P.base)
                if sec and sec['name'] in ('.data','.bigarr'):
                    targets.setdefault(t,[]).append(ins.address)
ks=sorted(targets)
print('distinct .data/.bigarr targets:', len(ks))
print()
print(f'{"addr":>14}{"refs":>6}  {"gap to next":>14}  note')
V=65536
interesting={12*V:'12B/vert (dvertex)',4*V:'4B/vert',32*V:'32B/vert',16*V:'16B/vert',8*V:'8B/vert',
             4*0x3e800:'4B/edge(stock)',16*0x3e800:'16B/edge(stock)',4*0x7d000:'4B/surfedge(stock)',
             2*V:'2B/vert', 56*0x10000:'56B/face', 0x10000*4:'4B/face'}
for i,k in enumerate(ks):
    nxt = ks[i+1] if i+1<len(ks) else None
    gap = (nxt-k) if nxt else 0
    note = interesting.get(gap,'')
    if gap >= 100000 or note:
        print(f'{k:14x}{len(targets[k]):6}  {gap:14}  {note}')
