import sys,re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
path=sys.argv[1]
p=PE(path); d=bytes(p.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
t=p.getsec('.text'); TA=p.base+t['va']; code=d[t['raw']:t['raw']+t['vs']]
ins=[]; seen=set()
for s in range(0,len(code),4096):
    for i in md.disasm(code[s:s+4200],TA+s):
        if i.address in seen: continue
        seen.add(i.address); ins.append(i)
ins.sort(key=lambda x:x.address)
def tgt(i):
    m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
    if not m: return None
    dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
    return i.address+i.size+dd
# 1. najti AddLump: funkciju, kotoruju zovut s ecx=0..63 mnogo raz
from collections import Counter
cc=Counter()
for k,i in enumerate(ins):
    if i.mnemonic=='call' and i.op_str.startswith('0x'):
        cc[i.op_str]+=1
cand=[a for a,n in cc.items() if n>=40]
print("%s" % path.split('/')[-1])
print("  kandidaty AddLump (>=40 vyzovov): %s" % cand)
# 2. dlja kazhdogo vyzova s ecx=0x10 - vzjat rdx i r8
for k,i in enumerate(ins):
    if i.mnemonic!='call' or i.op_str not in cand: continue
    lump=None; arr=None; akind=None; cnt=None; ops=[]
    for y in ins[max(0,k-14):k]:
        o=y.op_str.split(', ')
        if len(o)>=2 and o[0] in ('ecx','rcx') and o[1].startswith('0x') and 'rip' not in y.op_str:
            lump=int(o[1],16)
        if len(o)>=2 and o[0]=='rdx' and tgt(y):
            arr=tgt(y); akind='UKAZATEL' if y.mnemonic=='mov' else 'massiv'
        if len(o)>=2 and o[0] in ('r8d','r8') and tgt(y): cnt=tgt(y)
        if 'r8' in y.op_str and y.mnemonic in ('shl','add','imul','lea'): ops.append('%s %s'%(y.mnemonic,y.op_str))
    if lump==16:
        print("\n  *** LEAFFACES (lump 16) ***")
        print("    vyzov po %012x (vozvrat %012x)" % (i.address,i.address+i.size))
        print("    massiv   %012x  (%s)" % (arr,akind) if arr else "    massiv ?")
        print("    schetchik %012x" % cnt if cnt else "    schetchik ?")
        for o in ops: print("      %s" % o)
