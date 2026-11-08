import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from refs import Refs
from capstone import *
SRC='/home/claude/vrad/vrad_v04.exe'; DST='/home/claude/vrad/vrad_v05.exe'
P=PE(SRC); d=bytearray(P.d); BASE=P.base
R=Refs(P); md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def al(x,a=0x1000): return (x+a-1)&~(a-1)
print("sobrano rip-ssylok: %d" % len(R.map))

# --- proverka: net li sravnenij schetchikov s 0x10000 ---
print("\nishchu proverki predelov vozle schetchikov granej:")
CNT={0x151028f00:'numfaces',0x1513a8f38:'numfaces_hdr',0x150b78ec0:'numorigfaces',0x151822f50:'numleaffaces'}
ins_at={}
for s,e in P.funcs:
    va=BASE+s; o=P.va2o(va)
    if o is None: continue
    for i in md.disasm(bytes(d[o:o+min(e-s,0x20000)]),va): ins_at[i.address]=i
seq=sorted(ins_at)
import bisect
found=0
for va,(off,dd,tg,mn,sz) in sorted(R.map.items()):
    if tg not in CNT: continue
    j=bisect.bisect_left(seq,va)
    for k in range(j,min(j+6,len(seq))):
        i2=ins_at[seq[k]]
        if i2.mnemonic in ('cmp','test') and ('0x10000' in i2.op_str or '0xffff' in i2.op_str):
            print("   %012x  %s -> %s   ;  %012x %s %s" % (va,mn,CNT[tg],i2.address,i2.mnemonic,i2.op_str)); found+=1
if not found: print("   net - vrad predelov ne proverjaet")

last=max(P.sec,key=lambda s:s['va']+max(s['vs'],s['rs']))
PATCH_RVA=al(last['va']+max(last['vs'],last['rs'])); WIDE_RVA=PATCH_RVA+0x1000
PATCH_VA=BASE+PATCH_RVA
F=262144*56; LF=262144*4
ITEMS=[('dleaffaces',0x151822f60,65536*2, LF),
       ('dfaces',    0x151028f10,65536*56,F),
       ('dfaces_hdr',0x1513a8f40,65536*56,F),
       ('dorigfaces',0x150b78ed0,65536*56,F)]
cur=BASE+WIDE_RVA; NEW={}
print("\n.patch rva %#x ; .wide rva %#x" % (PATCH_RVA,WIDE_RVA))
for nm,ov,ob,nb in ITEMS:
    NEW[nm]=cur; print("  %-11s %012x -> %012x  (%s bajt)" % (nm,ov,cur,format(nb,','))); cur+=al(nb)
WIDE_VSIZE=cur-(BASE+WIDE_RVA)
print()
for nm,ov,ob,nb in ITEMS:
    n=0
    for va,(off,dd,tg,mn,sz) in sorted(R.map.items()):
        if not (ov<=tg<ov+ob): continue
        nd=NEW[nm]+(tg-ov)-(va+sz)
        assert -2**31<=nd<2**31
        assert struct.unpack_from('<i',d,off)[0]==dd
        struct.pack_into('<i',d,off,nd); n+=1
        if tg!=ov: print("     %s +%d : %012x" % (nm,tg-ov,va))
    print("  %-11s perenes ssylok: %-3d  absoljutnyh qword: %d" % (nm,n,bytes(d).count(struct.pack('<Q',ov))))
    assert n>0

def h(s): return bytes.fromhex(s.replace(' ',''))
def put(va,old,new):
    assert len(old)==len(new),(hex(va),len(old),len(new))
    o=P.va2o(va); c2=bytes(d[o:o+len(old)])
    assert c2==old,"%012x: %s != %s"%(va,c2.hex(),old.hex())
    d[o:o+len(new)]=new
def r32(end,to):
    v=to-end; assert -2**31<=v<2**31; return struct.pack('<i',v)
stubs=[]; sc=PATCH_VA
def stub(nm,body,back):
    global sc
    va=sc; b=body+h('e9')+r32(va+len(body)+5,back); stubs.append((nm,va,b)); sc=va+len(b); return va
sL=stub('zagruzchik /4', h('45 89 c6 41 c1 ee 02'), 0x14000c220)
s1=stub('potrebitel 1',  h('45 0f b7 4f 1e 41 c1 e1 10 66 45 0b 4f 14'), 0x14004eae2)
s2=stub('potrebitel 2',  h('0f b7 4b 1e c1 e1 10 66 0b 4b 14 44 01 f9 41 8b 0c 8a'), 0x1400664d7)
s3=stub('potrebitel 3',  h('41 0f b7 4b 1e c1 e1 10 66 41 0b 4b 14 48 01 f1 41 8b 3c 88'), 0x14006bdbd)
s4=stub('potrebitel 4',  h('44 0f b7 70 1e 41 c1 e6 10 66 44 0b 70 14 4d 01 ce 47 8b 34 b2'), 0x14007472d)
PATCH=bytearray(0x1000)
print()
for nm,va,b in stubs:
    PATCH[va-PATCH_VA:va-PATCH_VA+len(b)]=b
    print("  tramplin %-14s %012x  %2d bajt" % (nm,va,len(b)))

put(0x14000c20a, h('41 f6 c0 01'), h('41 f6 c0 03'))
put(0x14000c21a, h('45 89 c6 41 d1 ee'), h('e9')+r32(0x14000c21f,sL)+h('90'))
put(0x14004eadd, h('45 0f b7 4f 14'), h('e9')+r32(0x14004eae2,s1))
put(0x14004eaf0, h('4e 8d 0c 4f'), h('4e 8d 0c 8f'))
put(0x14004eb00, h('47 0f b7 1c 51'), h('47 8b 1c 91 90'))
put(0x1400664cb, h('0f b7 4b 14 44 01 f9 41 0f b7 0c 4a'), h('e9')+r32(0x1400664d0,s2)+h('90'*7))
put(0x14006bdb0, h('41 0f b7 4b 14 48 01 f1 41 0f b7 3c 48'), h('e9')+r32(0x14006bdb5,s3)+h('90'*8))
put(0x140074720, h('44 0f b7 70 14 4d 01 ce 47 0f b7 34 72'), h('e9')+r32(0x140074725,s4)+h('90'*8))
W=0x14000f7ae
newW = h('41 c1 e0 02') + h('48 8d 15')+r32(W+4+7,NEW['dleaffaces']) + h('31 c9 b1 10 45 31 c9')
assert len(newW)==18
o=P.va2o(W); assert bytes(d[o:o+3])==h('45 01 c0'), bytes(d[o:o+3]).hex()
d[o:o+18]=newW
print("\n  pisatel lampy 16: dlina = count*4, massiv -> %012x" % NEW['dleaffaces'])

pe=P.pe; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz; falign=struct.unpack_from('<I',d,pe+24+36)[0]
raw=(len(d)+falign-1)&~(falign-1); d.extend(b'\0'*(raw-len(d))); d.extend(PATCH)
ho=so+nsec*40
assert all(b==0 for b in d[ho:ho+80]), "net mesta pod dva zagolovka"
struct.pack_into('<8sIIII',d,ho,    b'.patch',0x1000,PATCH_RVA,0x1000,raw)
struct.pack_into('<I',d,ho+36,0x60000020)
struct.pack_into('<8sIIII',d,ho+40, b'.wide', WIDE_VSIZE,WIDE_RVA,0,0)
struct.pack_into('<I',d,ho+76,0xc0000080)
struct.pack_into('<H',d,pe+6,nsec+2)
soi=pe+24+56
old_si=struct.unpack_from('<I',d,soi)[0]; new_si=al(WIDE_RVA+WIDE_VSIZE)
struct.pack_into('<I',d,soi,new_si)
print("  sekcij %d -> %d ; .wide vsize %#x ; SizeOfImage %#x -> %#x" % (nsec,nsec+2,WIDE_VSIZE,old_si,new_si))
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
