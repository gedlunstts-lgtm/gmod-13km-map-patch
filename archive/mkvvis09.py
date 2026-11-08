import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from refs import Refs
SRC='/home/claude/vbsp/vvis_v06.exe'; DST='/home/claude/vbsp/vvis_v09.exe'
P=PE(SRC); d=bytearray(P.d); BASE=P.base
R=Refs(P)
def al(x,a=0x1000): return (x+a-1)&~(a-1)
print("sobrano rip-ssylok: %d" % len(R.map))

last=max(P.sec,key=lambda s:s['va']+max(s['vs'],s['rs']))
PATCH_RVA=al(last['va']+max(last['vs'],last['rs']))
WIDE_RVA=PATCH_RVA+0x1000
PATCH_VA=BASE+PATCH_RVA
print("poslednjaja sekcija %s ; .patch rva %#x ; .wide rva %#x" % (last['name'],PATCH_RVA,WIDE_RVA))

F=262144*56; LF=262144*4
ITEMS=[('dleaffaces',0x1517bfd80,65536*2, LF),
       ('dfaces',    0x150fc5d30,65536*56,F),
       ('dfaces_hdr',0x151345d60,65536*56,F),
       ('dorigfaces',0x150b15cf0,65536*56,F)]
cur=BASE+WIDE_RVA; NEW={}
for nm,ov,ob,nb in ITEMS:
    NEW[nm]=cur; print("  %-11s %012x -> %012x  (%s bajt)" % (nm,ov,cur,format(nb,',')))
    cur+=al(nb)
WIDE_VSIZE=cur-(BASE+WIDE_RVA)

print()
for nm,ov,ob,nb in ITEMS:
    n=0
    for va,(off,dd,tg,mn,sz) in sorted(R.map.items()):
        if not (ov<=tg<ov+ob): continue
        nt=NEW[nm]+(tg-ov); nd=nt-(va+sz)
        assert -2**31<=nd<2**31
        assert struct.unpack_from('<i',d,off)[0]==dd
        struct.pack_into('<i',d,off,nd); n+=1
        if tg!=ov: print("     %s +%d : %012x" % (nm,tg-ov,va))
    print("  %-11s perenes ssylok: %-3d  absoljutnyh qword: %d" % (nm,n,bytes(d).count(struct.pack('<Q',ov))))
    assert n>0

def h(s): return bytes.fromhex(s.replace(' ',''))
def put(va,old,new):
    assert len(old)==len(new),(hex(va),len(old),len(new))
    o=P.va2o(va); cur2=bytes(d[o:o+len(old)])
    assert cur2==old,"%012x: %s != %s"%(va,cur2.hex(),old.hex())
    d[o:o+len(new)]=new
def r32(end,to):
    v=to-end; assert -2**31<=v<2**31; return struct.pack('<i',v)

stubs=[]; sc=PATCH_VA
def stub(nm,body,back):
    global sc
    va=sc; b=body+h('e9')+r32(va+len(body)+5,back); stubs.append((nm,va,b)); sc=va+len(b); return va
sL=stub('zagruzchik /4',   h('45 89 c6 41 c1 ee 02'), 0x140009bd0)
sA=stub('potrebitel A',    h('41 0f b7 40 14 41 0f b7 48 1e c1 e1 10 09 c8'), 0x1400381f0)
sB=stub('potrebitel B',    h('41 0f b7 47 14 41 0f b7 4f 1e c1 e1 10 09 c8 4c 01 e8 8b 04 87'), 0x14003288c)
PATCH=bytearray(0x1000)
print()
for nm,va,b in stubs:
    PATCH[va-PATCH_VA:va-PATCH_VA+len(b)]=b
    print("  tramplin %-14s %012x  %2d bajt" % (nm,va,len(b)))

put(0x140009bba, h('41 f6 c0 01'), h('41 f6 c0 03'))
put(0x140009bca, h('45 89 c6 41 d1 ee'), h('e9')+r32(0x140009bcf,sL)+h('90'))
put(0x1400381eb, h('41 0f b7 40 14'), h('e9')+r32(0x1400381f0,sA))
put(0x1400381f7, h('4c 8d 0c 41'), h('4c 8d 0c 81'))
put(0x140038268, h('43 0f b7 04 51'), h('43 8b 04 91 90'))
put(0x140032880, h('41 0f b7 47 14 4c 01 e8 0f b7 04 47'), h('e9')+r32(0x140032885,sB)+h('90'*7))
# PISATEL lampy 16: dlina count*4, lump v cl, massiv - novyj
W=0x14000d15e
newW = h('41 c1 e0 02') + h('48 8d 15')+r32(W+4+7,NEW['dleaffaces']) + h('31 c9 b1 10 45 31 c9')
assert len(newW)==18, len(newW)
o=P.va2o(W)
assert bytes(d[o:o+3])==h('45 01 c0') or bytes(d[o:o+3])==h('41 01 c0'), bytes(d[o:o+3]).hex()
d[o:o+18]=newW
print("\n  pisatel lampy 16: dlina = count*4, massiv -> %012x" % NEW['dleaffaces'])

pe=P.pe; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz; falign=struct.unpack_from('<I',d,pe+24+36)[0]
raw=(len(d)+falign-1)&~(falign-1); d.extend(b'\0'*(raw-len(d))); d.extend(PATCH)
ho=so+nsec*40
assert all(b==0 for b in d[ho:ho+80]), "net mesta pod dva zagolovka"
struct.pack_into('<8sIIII',d,ho,     b'.patch',0x1000,PATCH_RVA,0x1000,raw)
struct.pack_into('<I',d,ho+36,0x60000020)
struct.pack_into('<8sIIII',d,ho+40,  b'.wide', WIDE_VSIZE,WIDE_RVA,0,0)
struct.pack_into('<I',d,ho+76,0xc0000080)
struct.pack_into('<H',d,pe+6,nsec+2)
soi=pe+24+56
old_si=struct.unpack_from('<I',d,soi)[0]; new_si=al(WIDE_RVA+WIDE_VSIZE)
struct.pack_into('<I',d,soi,new_si)
print("  sekcij %d -> %d ; .wide vsize %#x ; SizeOfImage %#x -> %#x" % (nsec,nsec+2,WIDE_VSIZE,old_si,new_si))
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
