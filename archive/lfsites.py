import sys,re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
path,arr,cnt=sys.argv[1],int(sys.argv[2],16),int(sys.argv[3],16)
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
print("%s   massiv %012x   schetchik %012x\n" % (path.split('/')[-1],arr,cnt))
for nm,T in (('MASSIV',arr),('SCHETCHIK',cnt)):
    print("======== %s %012x ========" % (nm,T))
    for k,i in enumerate(ins):
        if tgt(i)!=T: continue
        kind='ZAPIS' if re.match(r'^(dword|qword|word) ptr \[rip',i.op_str) else 'chtenie/adres'
        print("\n  -- %012x  %-22s %s %s   [%s]" % (i.address,i.bytes.hex(),i.mnemonic,i.op_str,kind))
        for y in ins[max(0,k-4):k+6]:
            if y.address==i.address: continue
            print("       %012x  %-20s %s %s" % (y.address,y.bytes.hex(),y.mnemonic,y.op_str))
