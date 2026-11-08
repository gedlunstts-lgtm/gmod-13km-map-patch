import sys,re,struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
stock,patched=sys.argv[1],sys.argv[2]
def load(path):
    p=PE(path); d=bytes(p.d)
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    t=p.getsec('.text'); TA=p.base+t['va']
    code=d[t['raw']:t['raw']+t['vs']]
    refs={}; seen=set()
    for s in range(0,len(code),4096):
        for i in md.disasm(code[s:s+4200],TA+s):
            if i.address in seen: continue
            seen.add(i.address)
            if 'rip' not in i.op_str: continue
            e=i.encoding
            if not e.disp_size: continue
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
            if not m: continue
            dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
            refs[i.address]=(i.address+i.size+dd,i.mnemonic,i.bytes.hex())
    return p,refs
ps,rs=load(stock); pp,rp=load(patched)
common=[a for a in rs if a in rp]
moved={}; same=[]
for a in common:
    if rs[a][1]!=rp[a][1]: continue
    if rs[a][0]!=rp[a][0]: moved[a]=(rs[a][0],rp[a][0])
    else: same.append(a)
print("%s -> %s" % (stock.split('/')[-1],patched.split('/')[-1]))
print("  obshchih rip-ssylok: %d ; perenesennyh: %d" % (len(common),len(moved)))
# gruppiruem po smeshcheniju
groups={}
for a,(o,n) in moved.items(): groups.setdefault(n-o,[]).append(o)
alladdr=sorted(set(v[0] for v in rs.values()))
import bisect
print("\n  gruppy perenosa:")
leaks=0
for delta,olds in sorted(groups.items(), key=lambda kv:-len(kv[1])):
    base=min(olds); top=max(olds)
    j=bisect.bisect_right(alladdr,top)
    nxt=alladdr[j] if j<len(alladdr) else top+1
    print("   delta %+#x : %d ssylok, bazy %012x..%012x, sledujushchij global %012x (zapas %#x)"
          % (delta,len(olds),base,top,nxt,nxt-base))
    bad=[a for a in same if base<=rs[a][0]<nxt]
    for a in bad:
        print("      !!! UTECHKA %012x  %s  -> %012x (+%d ot bazy)" % (a,rs[a][2],rs[a][0],rs[a][0]-base))
        leaks+=1
print("\n  VSEGO UTECHEK: %d" % leaks)
