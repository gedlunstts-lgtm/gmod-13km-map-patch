"""Poisk VSEH rip-ssylok na adres gruboj siloj po smeshchenijam, bez dizassemblera."""
import sys,struct,re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
path=sys.argv[1]; targets=[int(a,16) for a in sys.argv[2:]]
p=PE(path); d=bytes(p.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
t=p.getsec('.text'); TA=p.base+t['va']; RAW=t['raw']; N=t['vs']
for T in targets:
    print("=== %012x ===" % T)
    hits=[]
    for off in range(0,N-4):
        disp=struct.unpack_from('<i',d,RAW+off)[0]
        for trail in (0,1,2,4):
            if TA+off+4+trail+disp==T:
                hits.append((off,trail)); break
    for off,trail in hits:
        # pytaemsja dekodirovat instrukciju, nachav do smeshchenija
        shown=False
        for back in range(2,11):
            o2=RAW+off-back
            if o2<RAW: continue
            for i in md.disasm(d[o2:o2+16], TA+off-back, 1):
                e=i.encoding
                if (e.disp_size==4 and 'rip' in i.op_str
                        and i.address+e.disp_offset==TA+off
                        and i.address+i.size==TA+off+4+trail):
                    print("   %012x  %-24s %s %s   (hvost %d)" % (i.address,i.bytes.hex(),i.mnemonic,i.op_str,trail))
                    shown=True
                break
            if shown: break
        if not shown:
            print("   smeshchenie po rva %#x (hvost %d) - instrukciju ne opoznal" % (t['va']+off,trail))
    print("   vsego: %d\n" % len(hits))
