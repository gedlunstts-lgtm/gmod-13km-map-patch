"""v21 = v20 + otkljuchenie proverki granic karty (to, chto delala faza +-32k).
   stok:    ja  error  (77 06) ; jae ok (73 18)
   nado:    nop nop    (90 90) ; jmp ok (eb 18)
"""
import sys, struct, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
h=lambda s: bytes.fromhex(s.replace(' ',''))

P=PE('/home/claude/fz2/engine_nov_v20.dll'); d=bytearray(P.d)
SITES=[(0x1802300a5, h('7706'), h('9090'), 'ja error -> nop nop'),
       (0x1802300ab, h('7318'), h('eb18'), 'jae ok  -> jmp ok')]
for va,old,new,what in SITES:
    o=P.va2o(va); cur=bytes(d[o:o+len(old)])
    assert cur==old, '%012x: %s != %s'%(va,cur.hex(),old.hex())
    d[o:o+len(new)]=new
    print('  %012x  %s  (%s -> %s)'%(va,what,old.hex(),new.hex()))
DST='/home/claude/fz2/engine_nov_v21.dll'
open(DST,'wb').write(bytes(d))
print('\n%s  MD5 %s'%(DST,hashlib.md5(bytes(d)).hexdigest()))
# proverka
Q=PE(DST)
print('\nproverka funkcii 0x180230050:')
for ins in Q.md.disasm(Q.read(0x180230085,0x50), 0x180230085):
    print('  %012x %-16s %s %s'%(ins.address,ins.bytes.hex(),ins.mnemonic,ins.op_str))
