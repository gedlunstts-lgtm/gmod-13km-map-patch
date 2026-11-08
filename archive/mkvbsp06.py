import sys, struct, re, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *

SRC='/home/claude/vbsp/vbsp_v05.exe'
DST='/home/claude/vbsp/vbsp_v06.exe'
P=PE(SRC); d=bytearray(P.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
BASE=P.base
def al(x,a=0x1000): return (x+a-1)&~(a-1)

OLD_ARR=0x151820db0          # dleaffaces  (65536 x u16)
CNT    =0x151820da0          # numleaffaces
NEWMAX =262144

big=P.getsec('.bigarr'); BIG_VA=BASE+big['va']; OLD_END=BIG_VA+big['vs']
NEW_ARR=OLD_END
ARR_BYTES=al(NEWMAX*4)
BIG_VSIZE=(NEW_ARR+ARR_BYTES)-BIG_VA
PATCH_RVA=(NEW_ARR+ARR_BYTES)-BASE
PATCH_VA=BASE+PATCH_RVA
print(".bigarr %012x vsize %#x konec %012x" % (BIG_VA,big['vs'],OLD_END))
print("  dleaffaces -> %012x  %d zapisej x4 = %#x bajt" % (NEW_ARR,NEWMAX,ARR_BYTES))
print("  .bigarr vsize -> %#x" % BIG_VSIZE)
print("  .patch -> rva %#x va %012x" % (PATCH_RVA,PATCH_VA))

# ---------- 1. perenos ssylok na massiv ----------
def fins(s,e):
    va=BASE+s; o=P.va2o(va)
    if o is None: return []
    buf=bytes(d[o:o+(e-s)]); out=[]; c=0
    while c<len(buf):
        got=False
        for i in md.disasm(buf[c:],va+c):
            got=True; out.append(i); c=i.address-va+i.size
        if not got: c+=1
    return out
n=0
for (s,e) in P.funcs:
    for ins in fins(s,e):
        if 'rip' not in ins.op_str: continue
        enc=ins.encoding
        if not enc.disp_size: continue
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
        if not m: continue
        dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
        if ins.address+ins.size+dd==OLD_ARR:
            nd=NEW_ARR-(ins.address+ins.size)
            assert -2**31<=nd<2**31
            off=P.va2o(ins.address)+enc.disp_offset
            assert struct.unpack_from('<i',d,off)[0]==dd
            struct.pack_into('<i',d,off,nd); n+=1
print("\n  perenes ssylok na massiv: %d" % n)
print("  absoljutnyh qword na staryj adres: %d" % bytes(d).count(struct.pack('<Q',OLD_ARR)))

# ---------- 2. pomoshchniki ----------
def put(va,old,new):
    assert len(old)==len(new), (va,len(old),len(new))
    o=P.va2o(va); cur=bytes(d[o:o+len(old)])
    assert cur==old, "%012x: %s != %s" % (va,cur.hex(),old.hex())
    d[o:o+len(new)]=new
def h(s): return bytes.fromhex(s.replace(' ',''))
def rel32(frm_end,to): 
    v=to-frm_end; assert -2**31<=v<2**31; return struct.pack('<i',v)

# ---------- 3. EmitLeafFace: 32 bita ----------
put(0x14007b651, h('4e 8d 0c 42'), h('4e 8d 0c 82'))   # lea r9,[rdx+r8*4]
put(0x14007b660, h('45 0f b7 11'), h('45 8b 11 90'))   # mov r10d,[r9]
put(0x14007b66c, h('49 83 c1 02'), h('49 83 c1 04'))   # add r9,4
put(0x14007b67c, h('81 f9 00 00 01 00'), h('81 f9')+struct.pack('<I',NEWMAX))
put(0x14007b687, h('66 89 04 4a'), h('89 04 8a 90'))   # mov [rdx+rcx*4],eax
put(0x14007b6ad, h('ba 00 00 01 00'), h('ba')+struct.pack('<I',NEWMAX))
print("\n  EmitLeafFace: shag 4, zapis 32 bita, predel %d" % NEWMAX)

# ---------- 4. WriteBSPFile: dlina x4 ----------
W=0x140011277
new = h('44 8b 05')+rel32(W+7,CNT) \
    + h('41 c1 e0 02') \
    + h('48 8d 15')+rel32(W+7+4+7,NEW_ARR) \
    + h('31 c9 b1 10') \
    + h('45 31 c9') \
    + h('e8')+rel32(W+7+4+7+4+3+5,0x140018f30)
assert len(new)==30, len(new)
o=P.va2o(W); d[o:o+30]=new
print("  WriteBSPFile: AddLump(16) dlina = count*4")

# ---------- 5. trampliny v .patch ----------
stubs=[]; cur=PATCH_VA
def stub(name, body_fn, back):
    global cur
    va=cur
    b=body_fn(va)
    b=b+h('e9')+rel32(va+len(b)+5,back)
    stubs.append((name,va,b)); cur=va+len(b)
    return va

# S1: firstleafface -> word[rsi+0x14] + starshie v word[rsi+0x1e]
s1=stub('firstleafface(EmitLeaf)', lambda va:
        h('8b 05')+rel32(va+6,CNT) + h('66 89 46 14 c1 e8 10 66 89 46 1e'),
        0x14007b968)
# S2: numleaffaces lista = cnt - firstleafface32
s2=stub('numleaffaces(EmitLeaf)', lambda va:
        h('8b 05')+rel32(va+6,CNT) + h('0f b7 4e 1e c1 e1 10 0f b7 56 14 09 d1 29 c8 66 89 46 16'),
        0x14007b9d3)
# S3: potrebitel 14007e4d0 - firstleafface iz r8
s3=stub('firstleafface(14007e4d0)', lambda va:
        h('41 0f b7 48 14 45 0f b7 58 1e 41 c1 e3 10 44 09 d9'),
        0x14007e591)
# S4: potrebitel 140070180 - firstleafface iz r15 + chtenie leafface
s4=stub('leafface(140070180)', lambda va:
        h('41 0f b7 47 14 45 0f b7 4f 1e 41 c1 e1 10 44 09 c8 4c 01 e8 8b 04 87'),
        0x14007023c)

PATCH=bytearray(0x1000)
for name,va,b in stubs:
    PATCH[va-PATCH_VA:va-PATCH_VA+len(b)]=b
    print("    %-26s %012x  %2d bajt" % (name,va,len(b)))

# zamena mest vyzova na jmp
def tojmp(va,oldlen,target,oldbytes):
    nb=h('e9')+rel32(va+5,target)+b'\x90'*(oldlen-5)
    put(va,oldbytes,nb)
tojmp(0x14007b95d,11,s1, h('0f b7 05 3c 54 7a 11 66 89 46 14'))
tojmp(0x14007b9c4,15,s2, h('0f b7 05 d5 53 7a 11 66 2b 46 14 66 89 46 16'))
tojmp(0x14007e58c, 5,s3, h('41 0f b7 48 14'))
tojmp(0x140070230,12,s4, h('41 0f b7 47 14 4c 01 e8 0f b7 04 47'))
# potrebitel 14007e4d0: shag massiva 2->4
put(0x14007e598, h('4c 8d 0c 4a'), h('4c 8d 0c 8a'))
put(0x14007e5df, h('41 0f b7 0c 59'), h('41 8b 0c 99 90'))
print("\n  perehody na trampliny postavleny, shag potrebitelej 2 -> 4")

# ---------- 6. PE: rastim .bigarr, dobavljaem .patch ----------
pe=P.pe
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
falign=struct.unpack_from('<I',d,pe+24+36)[0]
for i in range(nsec):
    o2=so+i*40
    if bytes(d[o2:o2+8]).split(b'\0')[0]==b'.bigarr':
        struct.pack_into('<I',d,o2+8,BIG_VSIZE)
raw=(len(d)+falign-1)&~(falign-1)
d.extend(b'\0'*(raw-len(d)))
d.extend(PATCH)
ho=so+nsec*40
assert all(b==0 for b in d[ho:ho+40]), "net mesta pod zagolovok sekcii"
struct.pack_into('<8sIIII',d,ho,b'.patch',0x1000,PATCH_RVA,0x1000,raw)
struct.pack_into('<I',d,ho+36,0x60000020)
struct.pack_into('<H',d,pe+6,nsec+1)
soi=pe+24+56
old_si=struct.unpack_from('<I',d,soi)[0]
new_si=al(PATCH_RVA+0x1000)
struct.pack_into('<I',d,soi,new_si)
print("\n  sekcij %d -> %d ; .patch raw %#x" % (nsec,nsec+1,raw))
print("  SizeOfImage %#x -> %#x" % (old_si,new_si))
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
