import sys, pickle, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
p = PE('/home/claude/fz/engine_fz.dll')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
def allins():
    for (s,e) in p.funcs:
        va = p.base+s; end=p.base+e
        o = p.va2o(va)
        if o is None: continue
        buf = bytes(p.d[o:o+(e-s)])
        cur = 0
        while cur < len(buf):
            got=False
            for ins in md.disasm(buf[cur:], va+cur):
                got=True
                yield ins
                cur = ins.address - va + ins.size
            if not got:
                cur += 1
if __name__=='__main__':
    n=0; h108=[]; h104=[]
    for ins in allins():
        n+=1
        s=ins.op_str
        if '+ 0x108]' in s and ins.mnemonic in ('mov','lea'):
            h108.append((ins.address, ins.mnemonic+' '+s))
        if '+ 0x104]' in s:
            h104.append((ins.address, ins.mnemonic+' '+s))
    print('insns',n)
    print('--- 0x108:',len(h108))
    for a,s in h108: print(f'{a:012x}  {s}')
    print('--- 0x104:',len(h104))
    for a,s in h104: print(f'{a:012x}  {s}')
