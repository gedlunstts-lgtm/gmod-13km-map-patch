import sys, struct, re, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
SRC='/home/claude/vbsp/vvis_v06.exe'; DST='/home/claude/vbsp/vvis_v07.exe'
P=PE(SRC); d=bytearray(P.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
BASE=P.base
def al(x,a=0x1000): return (x+a-1)&~(a-1)
OLD_ARR=0x1517bfd80; OLD_SZ=65536*2
NEWMAX=262144
big=P.getsec('.bigarr'); BIG_VA=BASE+big['va']; OLD_END=BIG_VA+big['vs']
NEW_ARR=OLD_END; ARRB=al(NEWMAX*4)
BIG_VSIZE=(NEW_ARR+ARRB)-BIG_VA
PATCH_RVA=(NEW_ARR+ARRB)-BASE; PATCH_VA=BASE+PATCH_RVA
print(".bigarr %012x vsize %#x -> %#x" % (BIG_VA,big['vs'],BIG_VSIZE))
print("  dleaffaces %012x -> %012x  (%d x4)" % (OLD_ARR,NEW_ARR,NEWMAX))
print("  .patch va %012x" % PATCH_VA)

# --- perenos ssylok (po diapazonu, s sohraneniem smeshchenija) ---
t=P.getsec('.text'); TA=BASE+t['va']; code=bytes(d[t['raw']:t['raw']+t['vs']])
n=0; seen=set()
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
        if not (OLD_ARR<=tg<OLD_ARR+OLD_SZ): continue
        nt=NEW_ARR+(tg-OLD_ARR); nd=nt-(i.address+i.size)
        assert -2**31<=nd<2**31
        fo=P.va2o(i.address)+e.disp_offset
        assert struct.unpack_from('<i',d,fo)[0]==dd
        struct.pack_into('<i',d,fo,nd); n+=1
        print("    ssylka %012x (+%d)" % (i.address,tg-OLD_ARR))
print("  perenes ssylok: %d ; absoljutnyh qword: %d" % (n,bytes(d).count(struct.pack('<Q',OLD_ARR))))

def h(s): return bytes.fromhex(s.replace(' ',''))
def put(va,old,new):
    assert len(old)==len(new),(hex(va),len(old),len(new))
    o=P.va2o(va); cur=bytes(d[o:o+len(old)])
    assert cur==old,"%012x: %s != %s"%(va,cur.hex(),old.hex())
    d[o:o+len(new)]=new
def r32(end,to):
    v=to-end; assert -2**31<=v<2**31; return struct.pack('<i',v)

# --- trampliny ---
stubs=[]; cur=PATCH_VA
def stub(name,body,back):
    global cur
    va=cur; b=body+h('e9')+r32(va+len(body)+5,back)
    stubs.append((name,va,b)); cur=va+len(b); return va
sL=stub('zagruzchik: count=len/4', h('45 89 c6 41 c1 ee 02'), 0x140009bd0)
sA=stub('potrebitel A: firstleafface', h('41 0f b7 40 14 41 0f b7 48 1e c1 e1 10 09 c8'), 0x1400381f0)
sB=stub('potrebitel B: leafface',      h('41 0f b7 47 14 41 0f b7 4f 1e c1 e1 10 09 c8 4c 01 e8 8b 04 87'), 0x14003288c)
PATCH=bytearray(0x1000)
for nm,va,b in stubs:
    PATCH[va-PATCH_VA:va-PATCH_VA+len(b)]=b
    print("    %-30s %012x  %2d bajt" % (nm,va,len(b)))

# --- pravki na meste ---
put(0x140009bba, h('41 f6 c0 01'), h('41 f6 c0 03'))                     # kratnost 2 -> 4
put(0x140009bca, h('45 89 c6 41 d1 ee'), h('e9')+r32(0x140009bcf,sL)+h('90'))
put(0x1400381eb, h('41 0f b7 40 14'), h('e9')+r32(0x1400381f0,sA))
put(0x1400381f7, h('4c 8d 0c 41'), h('4c 8d 0c 81'))                     # shag 2 -> 4
put(0x140038268, h('43 0f b7 04 51'), h('43 8b 04 91 90'))               # chtenie 32 bita
put(0x140032880, h('41 0f b7 47 14 4c 01 e8 0f b7 04 47'), h('e9')+r32(0x140032885,sB)+h('90'*7))
print("  pravki na meste postavleny")

# --- PE ---
pe=P.pe; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz; falign=struct.unpack_from('<I',d,pe+24+36)[0]
for i in range(nsec):
    o2=so+i*40
    if bytes(d[o2:o2+8]).split(b'\0')[0]==b'.bigarr': struct.pack_into('<I',d,o2+8,BIG_VSIZE)
raw=(len(d)+falign-1)&~(falign-1); d.extend(b'\0'*(raw-len(d))); d.extend(PATCH)
ho=so+nsec*40
assert all(b==0 for b in d[ho:ho+40]), "net mesta pod zagolovok"
struct.pack_into('<8sIIII',d,ho,b'.patch',0x1000,PATCH_RVA,0x1000,raw)
struct.pack_into('<I',d,ho+36,0x60000020)
struct.pack_into('<H',d,pe+6,nsec+1)
soi=pe+24+56
old_si=struct.unpack_from('<I',d,soi)[0]; new_si=al(PATCH_RVA+0x1000)
struct.pack_into('<I',d,soi,new_si)
print("  sekcij %d -> %d ; SizeOfImage %#x -> %#x" % (nsec,nsec+1,old_si,new_si))
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
