"""Poisk vbitych konstant-predelov (0x10000 i okolo) v ciklah rosta vektorov."""
import sys,re,struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from refs import Refs
from capstone import *
path=sys.argv[1]
p=PE(path); d=bytes(p.d)
R=Refs(p); md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
ins={}
for s,e in p.funcs:
    va=p.base+s; o=p.va2o(va)
    if o is None: continue
    for i in md.disasm(bytes(d[o:o+min(e-s,0x20000)]),va): ins[i.address]=i
seq=sorted(ins)
import bisect
print("%s\n" % path.split('/')[-1])
print("cikly udvoenija s vbitym predelom (lea ecx,[rax+rax] / cmp ... jl):\n")
found=[]
for k,va in enumerate(seq):
    i=ins[va]
    if i.mnemonic!='cmp': continue
    m=re.match(r'^(e[a-z]{2}|r\d+d), (0x[0-9a-f]+)$', i.op_str)
    if not m: continue
    lim=int(m.group(2),16)
    if lim not in (0x8000,0xffff,0x10000,0x20000,0x40000): continue
    # rjadom dolzhen byt lea reg,[reg+reg] i jl nazad
    win=[ins[seq[q]] for q in range(max(0,k-4),min(len(seq),k+3))]
    has_dbl=any(y.mnemonic=='lea' and re.search(r'\[(r?[a-z0-9]+) \+ \1\]',y.op_str) for y in win)
    has_jl=any(y.mnemonic in ('jl','jb') and y.op_str.startswith('0x') and int(y.op_str,16)<va for y in win)
    if not (has_dbl and has_jl): continue
    # najdem ukazatel/schetchik, kotoryj pishut dalshe
    ptr=None; cntv=None
    for q in range(k,min(len(seq),k+14)):
        y=ins[seq[q]]; t=R.map.get(y.address)
        if not t: continue
        if y.mnemonic=='mov' and y.op_str.startswith('dword ptr [rip') and cntv is None: cntv=t[2]
        if y.mnemonic=='mov' and y.op_str.startswith('qword ptr [rip') and ptr is None: ptr=t[2]
    found.append((va,lim,ptr,cntv))
    print("  %012x  cmp %s, %#x   ->  ukazatel %s  schetchik %s" % (
        va,m.group(1),lim,('%012x'%ptr) if ptr else '?',('%012x'%cntv) if cntv else '?'))
print("\nvsego: %d" % len(found))
