import sys,re,struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
path=sys.argv[1] if len(sys.argv)>1 else '/home/claude/vbsp/vbsp_v06.exe'
p=PE(path); d=bytes(p.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
# starye diapazony perenesennyh massivov
OLD=[('dfaces',       0x151026d60, 65536*56),
     ('dfaces_hdr',   0x1513a6d90, 65536*56),
     ('dorigfaces',   0x150b76d20, 65536*56),
     ('dleaffaces',   0x151820db0, 65536*2),
     ('dvertexes',    0x1504cbc50, 65536*12),
     ('dedges',       0x1505cbc40, 0),
     ]
OLD=[(n,a,s) for n,a,s in OLD if s>0]
t=p.getsec('.text'); TA=p.base+t['va']
code=d[t['raw']:t['raw']+t['vs']]
print("skaniruju .text %012x .. %012x (%d bajt), lineino" % (TA,TA+t['vs'],t['vs']))
hits={n:[] for n,a,s in OLD}
# lineinyj prohod s vyravnivaniem po kazhdomu bajtu - nadezhnee .pdata
seen=set()
for start in range(0,len(code),4096):
    for ins in md.disasm(code[start:start+4200], TA+start):
        if ins.address in seen: continue
        seen.add(ins.address)
        if 'rip' not in ins.op_str: continue
        e=ins.encoding
        if not e.disp_size: continue
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
        if not m: continue
        dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
        tg=ins.address+ins.size+dd
        for n,a,s in OLD:
            if a<=tg<a+s:
                hits[n].append((ins.address,tg-a,ins.mnemonic,ins.op_str,ins.bytes.hex()))
for n,a,s in OLD:
    h=hits[n]
    print("\n=== %s  staryj %012x..%012x : OSTALOS %d ssylok ===" % (n,a,a+s,len(h)))
    for addr,off,mn,ops,by in h[:40]:
        print("   %012x  +%-8d %-22s %s %s" % (addr,off,by,mn,ops))
print("\n=== absoljutnye 8-bajtnye konstanty v starye diapazony ===")
for n,a,s in OLD:
    cnt=0
    for off in range(0,len(d)-8):
        v=struct.unpack_from('<Q',d,off)[0]
        if a<=v<a+s: cnt+=1
    if cnt: print("   %s: %d" % (n,cnt))
print("gotovo")
