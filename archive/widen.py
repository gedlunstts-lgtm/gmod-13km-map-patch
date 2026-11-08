"""Perenos statichnyh massivov v .bigarr s sohraneniem smeshchenija vnutr zapisi.
   Vyzov: widen.py <src> <dst> name:oldva:oldbytes:newbytes [...]"""
import sys, struct, re, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
src,dst=sys.argv[1],sys.argv[2]
items=[]
for a in sys.argv[3:]:
    nm,ov,ob,nb=a.split(':')
    items.append((nm,int(ov,16),int(ob,0),int(nb,0)))
P=PE(src); d=bytearray(P.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
BASE=P.base
def al(x,a=0x1000): return (x+a-1)&~(a-1)
# novye massivy kladem v otdelnuju sekciju za vsemi sushchestvujushchimi
last=max(P.sec, key=lambda s2: s2['va']+max(s2['vs'],s2['rs']))
SEC_RVA=al(last['va']+max(last['vs'],last['rs']))
cur=BASE+SEC_RVA
NEW={}
print("%s -> %s" % (src.split('/')[-1],dst.split('/')[-1]))
print("poslednjaja sekcija %s konec rva %#x ; novaja sekcija .bigarr2 rva %#x" % (last['name'],last['va']+max(last['vs'],last['rs']),SEC_RVA))
for nm,ov,ob,nb in items:
    NEW[ov]=cur
    print("  %-14s %012x (%s bajt) -> %012x (%s bajt)" % (nm,ov,format(ob,','),cur,format(nb,',')))
    cur+=al(nb)
SEC_VSIZE=cur-(BASE+SEC_RVA)
t=P.getsec('.text'); TA=BASE+t['va']; code=bytes(d[t['raw']:t['raw']+t['vs']])
tot={ov:0 for _,ov,_,_ in items}; seen=set()
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
        tg=i.address+i.size+dd
        for nm,ov,ob,nb in items:
            if not (ov<=tg<ov+ob): continue
            nt=NEW[ov]+(tg-ov); nd=nt-(i.address+i.size)
            assert -2**31<=nd<2**31,(nm,hex(i.address))
            fo=P.va2o(i.address)+e.disp_offset
            assert struct.unpack_from('<i',d,fo)[0]==dd
            struct.pack_into('<i',d,fo,nd); tot[ov]+=1
            if tg!=ov: print("     +%d vnutr zapisi: %012x" % (tg-ov,i.address))
            break
print()
for nm,ov,ob,nb in items:
    print("  %-14s perenes ssylok: %-3d   absoljutnyh qword: %d" % (nm,tot[ov],bytes(d).count(struct.pack('<Q',ov))))
    assert tot[ov]>0, "%s: ni odnoj ssylki - adres neveren" % nm
pe=P.pe; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
ho=so+nsec*40
assert all(b==0 for b in d[ho:ho+40]), "net mesta pod zagolovok sekcii"
struct.pack_into('<8sIIII',d,ho,b'.bigarr2',SEC_VSIZE,SEC_RVA,0,0)
struct.pack_into('<I',d,ho+36,0xc0000080)
struct.pack_into('<H',d,pe+6,nsec+1)
soi=pe+24+56
old_si=struct.unpack_from('<I',d,soi)[0]
new_si=al(SEC_RVA+SEC_VSIZE)
struct.pack_into('<I',d,soi,new_si)
print("\n  sekcij %d -> %d ; .bigarr2 vsize %#x ; SizeOfImage %#x -> %#x" % (nsec,nsec+1,SEC_VSIZE,old_si,new_si))
open(dst,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (dst,hashlib.md5(bytes(d)).hexdigest()))
