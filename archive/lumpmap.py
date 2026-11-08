import sys,re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
from collections import defaultdict
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
idx={i.address:k for k,i in enumerate(ins)}
def tgt(i):
    m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
    if not m: return None
    dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
    return i.address+i.size+dd
# AddLump = cel vyzova s naibolshim chislom RAZLICHNYH imm v ecx pered vyzovom
dist=defaultdict(set)
for k,i in enumerate(ins):
    if i.mnemonic!='call' or not i.op_str.startswith('0x'): continue
    for y in ins[max(0,k-10):k]:
        o=y.op_str.split(', ')
        if y.mnemonic=='mov' and len(o)==2 and o[0]=='ecx' and o[1].startswith('0x') and 'rip' not in y.op_str:
            v=int(o[1],16)
            if 0<=v<64: dist[i.op_str].add(v)
if not dist: print("  AddLump ne najden"); sys.exit()
best=max(dist.items(), key=lambda kv:len(kv[1]))
AL=best[0]
print("%s" % path.split('/')[-1])
print("  AddLump = %s  (razlichnyh lampov: %d)" % (AL,len(best[1])))
print()
for k,i in enumerate(ins):
    if i.mnemonic!='call' or i.op_str!=AL: continue
    lump=arr=akind=cnt=None; ops=[]
    for y in ins[max(0,k-14):k]:
        o=y.op_str.split(', ')
        if y.mnemonic=='mov' and len(o)==2 and o[0]=='ecx' and o[1].startswith('0x') and 'rip' not in y.op_str:
            v=int(o[1],16)
            if 0<=v<64: lump=v
        if len(o)>=2 and o[0]=='rdx' and tgt(y):
            arr=tgt(y); akind='UKAZ' if y.mnemonic=='mov' else 'mass'
        if len(o)>=2 and o[0] in ('r8d','r8') and tgt(y): cnt=tgt(y)
        if ('r8d' in y.op_str or 'r8,' in y.op_str) and y.mnemonic in ('shl','add','imul','lea'):
            ops.append('%s %s'%(y.mnemonic,y.op_str))
    if lump is None: continue
    mk='   <<<<<<' if lump==16 else ''
    print("  lump %-4d ret=%012x  %s %s  cnt=%s  %s%s" % (
        lump, i.address+i.size, akind or '?', '%012x'%arr if arr else '?'*12,
        '%012x'%cnt if cnt else '?'*12, '; '.join(ops[-2:]), mk))
