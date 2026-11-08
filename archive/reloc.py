"""Nadezhnyj perenos statichnyh massivov v novuju sekciju .bigarr2.
   Ssylki sobirajutsja cherez Refs (pdata + linejno), s sohraneniem smeshchenija.
   Vyzov: reloc.py <src> <dst> name:oldva:oldbytes:newbytes [...]"""
import sys, struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from refs import Refs

src,dst=sys.argv[1],sys.argv[2]
items=[]
for a in sys.argv[3:]:
    nm,ov,ob,nb=a.split(':')
    items.append((nm,int(ov,16),int(ob,0),int(nb,0)))
P=PE(src); d=bytearray(P.d); BASE=P.base
def al(x,a=0x1000): return (x+a-1)&~(a-1)
last=max(P.sec,key=lambda s:s['va']+max(s['vs'],s['rs']))
SEC_RVA=al(last['va']+max(last['vs'],last['rs'])); cur=BASE+SEC_RVA
NEW={}
print("%s -> %s"%(src.split('/')[-1],dst.split('/')[-1]))
print("novaja sekcija .bigarr2 rva %#x"%SEC_RVA)
for nm,ov,ob,nb in items:
    NEW[ov]=cur
    print("  %-12s %012x (%s B) -> %012x (%s B)"%(nm,ov,format(ob,','),cur,format(nb,',')))
    cur+=al(nb)
SEC_VSIZE=cur-(BASE+SEC_RVA)

R=Refs(P); total=0
for nm,ov,ob,nb in items:
    hits=R.in_range(ov,ob)
    for ia,(fo,disp,ta,mn,sz) in sorted(hits.items()):
        newt=NEW[ov]+(ta-ov)
        struct.pack_into('<i',d,fo,newt-(ia+sz))
        total+=1
    print("  %-12s perenesено ssylok: %d"%(nm,len(hits)))
print("vsego pravok ssylok:",total)

# --- novyj zagolovok sekcii ---
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
opt=struct.unpack_from('<H',d,pe+20)[0]
ho=pe+24+opt+nsec*40
assert all(b==0 for b in d[ho:ho+40]), "net mesta pod zagolovok sekcii"
struct.pack_into('<8sIIII',d,ho,b'.bigarr2',SEC_VSIZE,SEC_RVA,0,0)
struct.pack_into('<IIHHI',d,ho+24,0,0,0,0,0xc0000080)
struct.pack_into('<H',d,pe+6,nsec+1)
old_si=struct.unpack_from('<I',d,pe+24+56)[0]
new_si=al(SEC_RVA+SEC_VSIZE)
struct.pack_into('<I',d,pe+24+56,new_si)
open(dst,'wb').write(bytes(d))
print("sekcij %d -> %d ; vsize %#x ; SizeOfImage %#x -> %#x"%(nsec,nsec+1,SEC_VSIZE,old_si,new_si))

# --- proverka: ni odnoj ostavshejsja ssylki v starye diapazony ---
Q=PE(dst); R2=Refs(Q); bad=0
for nm,ov,ob,nb in items:
    h=R2.in_range(ov,ob)
    if h:
        bad+=len(h)
        for ia,v in sorted(h.items()): print("   OSTALOS %012x -> %012x (%s)"%(ia,v[2],nm))
print("ostatochnyh ssylok:",bad)
