import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
SRC='/home/claude/fz/engine_v04.dll'; DST='/home/claude/fz/engine_v05.dll'
P=PE(SRC); d=bytearray(P.d)
def h(s): return bytes.fromhex(s.replace(' ',''))
def put(va,old,new,what):
    assert len(old)==len(new),(hex(va),len(old),len(new))
    o=P.va2o(va); cur=bytes(d[o:o+len(old)])
    assert cur==old,"%012x: %s != %s"%(va,cur.hex(),old.hex())
    d[o:o+len(new)]=new
    print("  %012x  %s" % (va,what))
def r32(end,to):
    v=to-end; assert -2**31<=v<2**31; return struct.pack('<i',v)
CAVE=0x180e51b70
stubs=[]; cur=CAVE
def stub(nm,body,back):
    global cur
    va=cur; b=body+h('e9')+r32(va+len(body)+5,back); stubs.append((nm,va,b)); cur=va+len(b); return va
def jmpto(va,oldbytes,target,back):
    n=len(oldbytes)
    assert n>=5
    put(va,oldbytes,h('e9')+r32(va+5,target)+h('90')*(n-5),'perehod na tramplin')

print("=== Mod_LoadMarksurfaces: lampa po 4 bajta ===")
put(0x180117390, h('a8 01'), h('a8 03'), 'kratnost dliny 2 -> 4')
put(0x1801173ae, h('48 c7 c1 ff ff ff ff 48 d1 eb'),
                h('31 c9 48 ff c9 48 c1 eb 02 90'), 'count = dlina/4')
put(0x180117420, h('0f b7 1c 7e'), h('8b 1c be 90'), 'chtenie zapisi 32 bita')

print("\n=== cikl kopirovanija lista: firstleafface 32 bita ===")
sL=stub('cikl lista', h('41 0f b7 41 06  66 41 89 40 1c'
                        '41 0f b7 41 10  66 41 89 40 22'
                        '41 0f b7 41 08  66 41 89 40 1e'), 0x180117144)
jmpto(0x180117130, h('41 0f b7 41 06 66 41 89 40 1c 41 0f b7 41 08 66 41 89 40 1e'), sL, 0x180117144)

print("\n=== shest chitatelej: vosstanovlenie 32-bitnogo indeksa ===")
R=[]
R.append(('1 @1800770c0', 0x1800770e4, h('44 0f b7 49 44'),
          h('44 0f b7 49 4a  41 c1 e1 10  66 44 0b 49 44'), 0x1800770e9))
R.append(('2 @1800e3388', 0x1800e3388, h('41 0f b7 4d 44'),
          h('41 0f b7 4d 4a  c1 e1 10  66 41 0b 4d 44'), 0x1800e338d))
R.append(('3 @1800e3781', 0x1800e37a0, h('0f b7 4e 44 48 8b 90 18 01 00 00'),
          h('0f b7 4e 4a  c1 e1 10  66 0b 4e 44  48 8b 90 18 01 00 00'), 0x1800e37ab))
R.append(('4 @1800efef7', 0x1800eff18, h('0f b7 4b 44 48 8b 82 18 01 00 00'),
          h('0f b7 4b 4a  c1 e1 10  66 0b 4b 44  48 8b 82 18 01 00 00'), 0x1800eff23))
R.append(('5 @18013d1e5', 0x18013d1fa, h('0f b7 55 44 85 c0'),
          h('0f b7 55 4a  c1 e2 10  66 0b 55 44  85 c0'), 0x18013d200))
R.append(('6 @18013d410', 0x18013d435, h('45 0f b7 50 44'),
          h('45 0f b7 50 4a  41 c1 e2 10  66 45 0b 50 44'), 0x18013d43a))
for nm,va,old,body,back in R:
    s=stub('chitatel '+nm, body, back)
    jmpto(va, old, s, back)

print("\ntrampliny v .cave:")
c=P.getsec('.cave')
for nm,va,b in stubs:
    o=c['raw']+(va-(P.base+c['va']))
    assert all(x==0 for x in d[o:o+len(b)]), "mesto v .cave zanjato: %s" % nm
    d[o:o+len(b)]=b
    print("  %-22s %012x  %2d bajt" % (nm,va,len(b)))
print("  itogo %d bajt, konec %012x" % (cur-CAVE,cur))
assert cur < P.base+c['va']+c['vs']
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
