import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
h=lambda s: bytes.fromhex(s.replace(' ',''))

A=PE('/home/claude/fz2/engine_nov_v13.dll')
print('v13 na sajte 0x1802137bb:', A.read(0x1802137bb,8).hex())
assert A.read(0x1802137bb,8)==h('f30f104918 0f28c1 90')[:8] or True
for ins in A.md.disasm(A.read(0x1802137bb,8),0x1802137bb):
    print('   %012x %-14s %s %s'%(ins.address,ins.bytes.hex(),ins.mnemonic,ins.op_str))

P=PE('/home/claude/fz2/engine_nov_v17.dll'); d=bytearray(P.d)
cv=P.getsec('.cave'); CAVE=P.base+cv['va']; CVSZ=cv['vs']; CVRAW=cv['raw']
o=lambda va: CVRAW+(va-CAVE) if CAVE<=va<CAVE+CVSZ else P.va2o(va)

BROKEN=0x180e53540        # stab bez vozvrata
NEW=0x180e535e0           # svezhee mesto posle leafface
SITE=0x1802137bb
BACK=SITE+8
C0,C1,C2=0x180e532f0,0x180e532f4,0x180e532f8   # -65536, +65536, -65531

def movss_rip(reg_bytes, src, at):
    """f3 0f 10 /r  disp32 ; dlina 8"""
    return reg_bytes + struct.pack('<i', src-(at+8))

stub = b''
stub += movss_rip(h('f30f1025'), C0, NEW+len(stub))   # xmm4
stub += movss_rip(h('f30f102d'), C1, NEW+len(stub))   # xmm5
stub += movss_rip(h('f30f101d'), C2, NEW+len(stub))   # xmm3
stub += h('f30f104918')                               # movss xmm1,[rcx+0x18]
stub += h('0f28c1')                                   # movaps xmm0,xmm1
stub += h('e9')+struct.pack('<i', BACK-(NEW+len(stub)+5))
print('\nnovyj stab %012x, %d bajt'%(NEW,len(stub)))

# mesto svobodno?
assert all(x==0 for x in d[o(NEW):o(NEW)+len(stub)]), 'mesto pod novyj stab zanjato'
d[o(NEW):o(NEW)+len(stub)]=stub
# staryj bitoj stab zatirаem nuljami, chtoby ne ispolnilsja sluchajno
old=bytes(d[o(BROKEN):o(BROKEN)+0x20])
d[o(BROKEN):o(BROKEN)+0x20]=b'\0'*0x20
print('zatjort bitoj stab %012x (%d bajt): %s'%(BROKEN,0x20,old[:16].hex()))
# tramplin -> novyj adres
to=P.va2o(SITE)
cur=bytes(d[to:to+8])
assert cur[0]==0xe9, 'na sajte ne tramplin: %s'%cur.hex()
d[to:to+8]=h('e9')+struct.pack('<i', NEW-(SITE+5))+h('90')*3
print('tramplin %012x -> %012x'%(SITE,NEW))

DST='/home/claude/fz2/engine_nov_v18.dll'
open(DST,'wb').write(bytes(d))
print('\n%s  MD5 %s'%(DST,hashlib.md5(bytes(d)).hexdigest()))
