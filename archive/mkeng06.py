import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
SRC='/home/claude/fz/engine_v05.dll'; DST='/home/claude/fz/engine_v06.dll'
P=PE(SRC); d=bytearray(P.d)
def h(s): return bytes.fromhex(s.replace(' ',''))
def r32(end,to):
    v=to-end; assert -2**31<=v<2**31; return struct.pack('<i',v)
CAVE=0x180e51c10   # posle tramplinov v05 (konec byl 180e51c0b)
cur=CAVE
# (adres, bajty movzx, bajty cmp, bajty jl, ok, err)
S=[(0x1800ea710, h('0f b7 86 78 05 00 00'), h('3b f8'), 0x1800ea72a, 0x1800ea71b),
   (0x1800ef03f, h('0f b7 86 78 05 00 00'), h('3b d8'), 0x1800ef059, 0x1800ef04a),
   (0x1800ef28c, h('41 0f b7 87 78 05 00 00'), h('3b d8'), 0x1800ef2ad, 0x1800ef298),
   (0x1800eff68, h('0f b7 85 78 05 00 00'), h('3b f8'), 0x1800eff82, 0x1800eff73),
   (0x1800f0165, h('41 0f b7 85 78 05 00 00'), h('3b d8'), 0x1800f0180, 0x1800f0171)]
print("granica CVarBitVec: sravnenie s m_numBits (16 bit) -> s m_numInts*32\n")
blobs=[]
for va,mv,cm,ok,err in S:
    n=len(mv)+len(cm)+2          # movzx + cmp + jl rel8
    o=P.va2o(va); cur_b=bytes(d[o:o+n])
    assert cur_b[:len(mv)]==mv, "%012x movzx: %s" % (va,cur_b.hex())
    assert cur_b[len(mv):len(mv)+2]==cm, "%012x cmp: %s" % (va,cur_b.hex())
    assert cur_b[len(mv)+2]==0x7c, "%012x jl: %s" % (va,cur_b.hex())
    mv2=bytearray(mv); mv2[-4]=0x7a          # 0x578 -> 0x57a
    body=bytes(mv2)+h('c1 e0 05')+cm
    body+=h('0f 8c')+r32(0,0)                # zaglushki, dopishem nizhe
    body+=h('e9')+r32(0,0)
    sva=cur
    # perescitaem perehody s uchetom adresa
    off_jl=len(mv2)+3+len(cm)
    body=bytearray(body)
    body[off_jl+2:off_jl+6]=r32(sva+off_jl+6,ok)
    body[off_jl+7:off_jl+11]=r32(sva+off_jl+11,err)
    body=bytes(body)
    blobs.append((va,n,sva,body))
    cur+=len(body)
    print("  %012x  (%d bajt) -> tramplin %012x  (%d bajt)   ok %012x  err %012x"
          % (va,n,sva,len(body),ok,err))
c=P.getsec('.cave')
for va,n,sva,body in blobs:
    o=P.va2o(va)
    d[o:o+n]=h('e9')+r32(va+5,sva)+h('90')*(n-5)
    co=c['raw']+(sva-(P.base+c['va']))
    assert all(x==0 for x in d[co:co+len(body)]), "mesto v .cave zanjato"
    d[co:co+len(body)]=body
print("\n  ispolzovano v .cave: %d bajt, konec %012x (predel %012x)"
      % (cur-CAVE,cur,P.base+c['va']+c['vs']))
assert cur < P.base+c['va']+c['vs']
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
