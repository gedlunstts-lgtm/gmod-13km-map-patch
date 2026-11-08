import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from sigfind import make_sig, find
from locate import find_bitvec_checks
from collections import Counter
h=lambda s: bytes.fromhex(s.replace(' ',''))
OLD='/home/claude/fz/engine_v04.dll'
SRC='/home/claude/fz2/engine_nov_stock.dll'
DST='/home/claude/fz2/engine_nov_v02.dll'
A=PE(OLD); B=PE(SRC)

# ---------- 1. novaja sekcija .cave ----------
d=bytearray(B.d)
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec,=struct.unpack_from('<H',d,pe+6)
SA,=struct.unpack_from('<I',d,pe+24+32)   # SectionAlignment
FA,=struct.unpack_from('<I',d,pe+24+36)   # FileAlignment
last=B.sec[-1]
cv_va = (last['va']+last['vs']+SA-1)//SA*SA
cv_raw= (len(d)+FA-1)//FA*FA
CVSZ  = 0x2000
d += b'\x00'*(cv_raw-len(d)) + b'\x00'*CVSZ
ent = pe+24+struct.unpack_from('<H',d,pe+20)[0]+nsec*40
struct.pack_into('<8sIIIIIIHHI',d,ent,b'.cave',CVSZ,cv_va,CVSZ,cv_raw,0,0,0,0,0x60000020)
struct.pack_into('<H',d,pe+6,nsec+1)
si=(cv_va+CVSZ+SA-1)//SA*SA
struct.pack_into('<I',d,pe+24+56,si)
CAVE=B.base+cv_va
print("sekcija .cave: va=%012x raw=%08x razmer=%d  SizeOfImage=%#x"%(CAVE,cv_raw,CVSZ,si))

def o_of(va):
    if CAVE<=va<CAVE+CVSZ: return cv_raw+(va-CAVE)
    return B.va2o(va)
def put(va,old,new,what):
    assert len(old)==len(new)
    o=o_of(va); cur=bytes(d[o:o+len(old)])
    assert cur==old,"%012x: %s != %s (%s)"%(va,cur.hex(),old.hex(),what)
    d[o:o+len(new)]=new; print("  %012x  %s"%(va,what))
def r32(end,to): return struct.pack('<i',to-end)

# ---------- 2. najti sajty signaturami ----------
def locate(old_va):
    for nb in (40,32,24,16):
        pat,msk,_=make_sig(A,old_va,nb)
        if len(find(A,pat,msk))==1:
            hits=find(B,pat,msk)
            if len(hits)==1: return hits[0]
    raise SystemExit("ne najden sajt %012x"%old_va)

S={k:locate(k) for k in (0x180117390,0x1801173ae,0x180117420,0x180117130,
                         0x1800770e4,0x1800e3388,0x1800e37a0,0x1800eff18,
                         0x18013d1fa,0x18013d435)}
for k,v in sorted(S.items()): print("  sajt %012x -> %012x  (%+#x)"%(k,v,v-k))

cur=CAVE; stubs=[]
def stub(nm,body,back):
    global cur
    va=cur; b=body+h('e9')+r32(va+len(body)+5,back); stubs.append((nm,va,b)); cur=va+len(b); return va
def jmpto(va,old,target):
    n=len(old); assert n>=5
    put(va,old,h('e9')+r32(va+5,target)+h('90')*(n-5),'perehod na tramplin')

print("\n=== Mod_LoadMarksurfaces: lampa po 4 bajta ===")
put(S[0x180117390], h('a8 01'), h('a8 03'), 'kratnost dliny 2 -> 4')
put(S[0x1801173ae], h('48 c7 c1 ff ff ff ff 48 d1 eb'),
                    h('31 c9 48 ff c9 48 c1 eb 02 90'), 'count = dlina/4')
put(S[0x180117420], h('0f b7 1c 7e'), h('8b 1c be 90'), 'chtenie zapisi 32 bita')

print("\n=== cikl kopirovanija lista ===")
vL=S[0x180117130]; backL=vL+0x14
sL=stub('cikl lista', h('41 0f b7 41 06  66 41 89 40 1c'
                        '41 0f b7 41 10  66 41 89 40 22'
                        '41 0f b7 41 08  66 41 89 40 1e'), backL)
jmpto(vL, h('41 0f b7 41 06 66 41 89 40 1c 41 0f b7 41 08 66 41 89 40 1e'), sL)

print("\n=== shest chitatelej ===")
R=[('1',0x1800770e4,h('44 0f b7 49 44'),          h('44 0f b7 49 4a  41 c1 e1 10  66 44 0b 49 44')),
   ('2',0x1800e3388,h('41 0f b7 4d 44'),          h('41 0f b7 4d 4a  c1 e1 10  66 41 0b 4d 44')),
   ('3',0x1800e37a0,h('0f b7 4e 44 48 8b 90 18 01 00 00'), h('0f b7 4e 4a  c1 e1 10  66 0b 4e 44  48 8b 90 18 01 00 00')),
   ('4',0x1800eff18,h('0f b7 4b 44 48 8b 82 18 01 00 00'), h('0f b7 4b 4a  c1 e1 10  66 0b 4b 44  48 8b 82 18 01 00 00')),
   ('5',0x18013d1fa,h('0f b7 55 44 85 c0'),       h('0f b7 55 4a  c1 e2 10  66 0b 55 44  85 c0')),
   ('6',0x18013d435,h('45 0f b7 50 44'),          h('45 0f b7 50 4a  41 c1 e2 10  66 45 0b 50 44'))]
for nm,ova,old,body in R:
    va=S[ova]; back=va+len(old)
    s=stub('chitatel '+nm, body, back)
    jmpto(va, old, s)

print("\n=== CBitVec: proverki granicy ===")
hits=find_bitvec_checks(B)
c=Counter(x['numbits_off'] for x in hits)
grp=[x for x in hits if c[x['numbits_off']]>=3]
print("  gruppa +%#x: %d sajtov"%(grp[0]['numbits_off'],len(grp)))
for x in grp:
    va=x['site']; span=x['span']
    body = h('0f b7')+bytes([0x80|0]) # zaglushka, sobirjom nizhe tochno
    # movzx eax, word [BASE + off+2]   -- berjom iz originalnyh bajt, pravim smeshchenie
    mv=bytearray(h(x['movzx']))
    # poslednie 4 bajta - smeshchenie (disp32)
    struct.pack_into('<i',mv,len(mv)-4,x['numbits_off']+2)
    # dstreg movzx -> eax: perepishem modrm reg-pole na 0 (eax)
    ridx = 1 if mv[0]==0x0f else 2       # prefiks REX?
    mv[ridx+1] = (mv[ridx+1] & 0xC7)     # reg = 000 = eax
    body = bytes(mv)+h('c1 e0 05')+h(x['cmpb'])
    # v cmp vtoroj operand dolzhen byt eax
    cb=bytearray(h(x['cmpb'])); cb[-1] = (cb[-1] & 0xF8)   # r/m = eax
    body = bytes(mv)+h('c1 e0 05')+bytes(cb)
    nxt=cur+len(body)
    full = body + h('0f 8c')+r32(nxt+6,x['ok']) + h('e9')+r32(nxt+6+5,x['err'])
    sv=cur; stubs.append(('bitvec %012x'%va, sv, full)); cur=sv+len(full)
    old=bytes(d[o_of(va):o_of(va)+span])
    put(va, old, h('e9')+r32(va+5,sv)+h('90')*(span-5), 'CBitVec -> tramplin')

print("\n=== konstanty limitov (iz predydushchej fazy) ===")
import re as _re
from capstone import Cs as _Cs, CS_ARCH_X86 as _AX, CS_MODE_64 as _M64
_md=_Cs(_AX,_M64); _md.detail=True
CONST=[(0x180113f31, 1999998,  'MAX_MAP_SURFEDGES 511998 -> 1999998'),
       (0x18017f1c0, 0x10000000,'VIS lump 16MB -> 256MB')]
for ova,newval,what in CONST:
    nva=locate(ova)
    o=o_of(nva)
    i=next(_md.disasm(bytes(d[o:o+16]),nva))
    assert i.mnemonic=='cmp', i.mnemonic
    e=i.encoding
    assert e.imm_size==4, e.imm_size
    off=o+e.imm_offset
    old=bytes(d[off:off+4]); new=struct.pack('<I',newval)
    d[off:off+4]=new
    print("  %012x  %-38s  %s -> %s"%(nva,what,old.hex(),new.hex()))


print("\ntrampliny:")
for nm,va,b in stubs:
    o=o_of(va); assert all(x==0 for x in d[o:o+len(b)]),"mesto zanjato: %s"%nm
    d[o:o+len(b)]=b
    print("  %-24s %012x  %2d bajt"%(nm,va,len(b)))
print("  itogo %d bajt iz %d"%(cur-CAVE,CVSZ))
assert cur<CAVE+CVSZ
open(DST,'wb').write(bytes(d))
print("\n%s  MD5 %s"%(DST,hashlib.md5(bytes(d)).hexdigest()))
