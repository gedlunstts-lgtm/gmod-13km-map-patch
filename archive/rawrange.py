"""Gruboj siloj: vse rip-ssylki, popadajushchie v zadannye diapazony."""
import sys,struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
path=sys.argv[1]
rngs=[]
for a in sys.argv[2:]:
    nm,lo,sz=a.split(':'); rngs.append((nm,int(lo,16),int(sz,0)))
p=PE(path); d=bytes(p.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
t=p.getsec('.text'); TA=p.base+t['va']; RAW=t['raw']; N=t['vs']
def decode(off,trail):
    for back in range(2,12):
        o2=RAW+off-back
        if o2<RAW: continue
        for i in md.disasm(d[o2:o2+16], TA+off-back, 1):
            try: e=i.encoding
            except Exception: break
            if (e.disp_size==4 and 'rip' in i.op_str
                    and i.address+e.disp_offset==TA+off
                    and i.address+i.size==TA+off+4+trail):
                return i
            break
    return None
tot=0
for nm,lo,sz in rngs:
    print("=== %s  %012x .. %012x ===" % (nm,lo,lo+sz))
    n=0
    for off in range(0,N-4):
        disp=struct.unpack_from('<i',d,RAW+off)[0]
        for trail in (0,1,2,4):
            tg=TA+off+4+trail+disp
            if not (lo<=tg<lo+sz): continue
            i=decode(off,trail)
            if i is None: continue
            print("   %012x  %-24s %s %s   (+%d)" % (i.address,i.bytes.hex(),i.mnemonic,i.op_str,tg-lo))
            n+=1; break
    print("   vsego: %d\n" % n); tot+=n
print("ITOGO: %d" % tot)
