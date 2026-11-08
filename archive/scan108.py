import sys, pickle, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
p = PE('/home/claude/fz/engine_fz.dll')
t = p.getsec('.text')
code = bytes(p.d[t['raw']:t['raw']+t['vs']])
base = p.base + t['va']
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
hits108=[]; hits104=[]
n=0
for ins in md.disasm(code, base):
    n+=1
    s = ins.op_str
    if '0x108]' in s and ins.mnemonic=='mov':
        hits108.append((ins.address, ins.mnemonic+' '+s))
    if '0x104]' in s:
        hits104.append((ins.address, ins.mnemonic+' '+s))
print('insns',n)
print('--- +0x108 mov sites:', len(hits108))
for a,s in hits108: print(f'{a:012x}  {s}')
print('--- +0x104 sites:', len(hits104))
for a,s in hits104: print(f'{a:012x}  {s}')
