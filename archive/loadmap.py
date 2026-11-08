import sys,re,bisect
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
path=sys.argv[1]; start=int(sys.argv[2],16); length=int(sys.argv[3],16)
p=PE(path); d=bytes(p.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
o=p.va2o(start); buf=d[o:o+length]
ins=[]; c=0
while c<len(buf):
    g=False
    for i in md.disasm(buf[c:],start+c):
        g=True; ins.append(i); c=i.address-start+i.size
    if not g: c+=1
def tgt(i):
    m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
    if not m: return None
    dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
    return i.address+i.size+dd
# vse adresa globalov, na kotorye voobshche est ssylki v .text - dlja ocenki vmestimosti
t=p.getsec('.text'); TA=p.base+t['va']; code=d[t['raw']:t['raw']+t['vs']]
glob=set(); seen=set()
for s in range(0,len(code),4096):
    for i in md.disasm(code[s:s+4200],TA+s):
        if i.address in seen: continue
        seen.add(i.address)
        x=tgt(i)
        if x and x>p.base+0x170000: glob.add(x)
G=sorted(glob)
def cap(a):
    j=bisect.bisect_right(G,a)
    return (G[j]-a) if j<len(G) else 0
# prohod: lump opredeljaem po [rdi+N] -> N=8+16*i  (fileofs) ili +4 (filelen)
print("%s   razbor zagruzchika s %012x\n" % (path.split('/')[-1],start))
print(" lump  elem  massiv          vmestimost     zapisej   nado(262144)  status")
print(" ----  ----  --------------  ----------  ----------  ------------  ------")
cur={}
for k,i in enumerate(ins):
    m=re.search(r'\[rdi \+ (0x[0-9a-f]+)\]',i.op_str)
    if m and i.mnemonic in ('mov',):
        off=int(m.group(1),16)
        if off>=8 and (off-8)%16 in (0,4) and (off-8)//16<64:
            cur['lump']=(off-8)//16
    if i.mnemonic in ('shr','sar') and 'r14d' in i.op_str:
        v=i.op_str.split(', ')[1]
        cur['div']=int(v,16) if v.startswith('0x') else int(v)
    if i.mnemonic=='imul' and len(i.op_str.split(', '))==3:
        cur['mul']=i.op_str.split(', ')[2]
    if i.mnemonic=='call' and 'lump' in cur:
        # posledniaja lea rcx pered call = priemnik
        arr=None
        for y in ins[max(0,k-8):k]:
            if y.mnemonic=='lea' and y.op_str.startswith('rcx,') and tgt(y): arr=tgt(y)
        if arr is None: cur.pop('lump',None); continue
        L=cur['lump']; dv=cur.get('div')
        elem = dv and (1<<dv) or None
        cp=cap(arr); n=cp//elem if elem else 0
        need=262144*elem if elem else 0
        st='OK' if elem and cp>=need else ('MALO' if elem else '?')
        print(" %4d  %4s  %012x  %10d  %10s  %12s  %s" % (
            L, elem if elem else '?', arr, cp, n if elem else '?', need if elem else '?', st))
        cur={}
