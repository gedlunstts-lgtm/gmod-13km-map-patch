import sys, struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
h=bytes.fromhex
SRC='/home/claude/fz/engine_v06.dll'; DST='/home/claude/fz/engine_v07.dll'
p=PE(SRC); d=bytearray(p.d)
def wr(va,b):
    o=p.va2o(va); d[o:o+len(b)]=b
def rd(va,n):
    o=p.va2o(va); return bytes(d[o:o+n])

# gde konchajutsja stuby v06
CAVE=0x180e51c10+117          # 0x180e51c85
LIM =0x180e52000
# vyrovnjaem na 16
CAVE=(CAVE+15)&~15
print("stuby s %012x, do %012x" % (CAVE,LIM))

# dva sajta: movzx eax,word[rsi+0x578] / cmp REG,eax / jl OK ; dalshe ERR
S=[ (0x1800eef9d, h('0f b7 86 78 05 00 00'), h('3b d8'), 0x1800eefb7, 0x1800eefa8),   # cmp ebx,eax  "invalid set"
    (0x1800efccc, h('0f b7 86 78 05 00 00'), h('3b f8'), 0x1800efce6, 0x1800efcd7) ]  # cmp edi,eax  "invalid IsBitSet"

cur=CAVE
for site,movzx_old,cmpb,ok,err in S:
    # proverjaem chto na meste imenno to chto zhdjom
    got=rd(site,11)
    exp=movzx_old+cmpb+h('7c')+bytes([ok-(site+11)])
    assert got==exp, "site %x: %s != %s" % (site,got.hex(),exp.hex())
    # stub
    stub =bytearray()
    stub+=h('0f b7 86 7a 05 00 00')          # movzx eax, word [rsi+0x57a]   m_numInts
    stub+=h('c1 e0 05')                      # shl eax, 5
    stub+=cmpb                               # cmp REG, eax
    nxt=cur+len(stub)
    stub+=h('0f 8c')+struct.pack('<i', ok-(nxt+6)); nxt+=6     # jl ok
    stub+=h('e9')+struct.pack('<i', err-(nxt+5))               # jmp err
    assert cur+len(stub)<=LIM
    wr(cur, bytes(stub))
    # v sajt: jmp rel32 na stub + nop
    patch=h('e9')+struct.pack('<i', cur-(site+5))+h('90'*6)
    assert len(patch)==11
    wr(site, patch)
    print("sajt %012x -> stub %012x (%d bajt)" % (site,cur,len(stub)))
    cur+=len(stub)
    cur=(cur+15)&~15
open(DST,'wb').write(bytes(d))
print("zapisan",DST)

# --- proverka dizassemblerom ---
q=PE(DST); md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
for site,_,_,ok,err in S:
    print("=== sajt %012x" % site)
    o=q.va2o(site)
    for i in md.disasm(bytes(q.d)[o:o+16], site): print("   %012x  %-8s %s"%(i.address,i.mnemonic,i.op_str))
for a in range(CAVE, cur, 1):
    pass
o=q.va2o(CAVE)
print("=== stuby ===")
for i in md.disasm(bytes(q.d)[o:o+(cur-CAVE)], CAVE):
    print("   %012x  %-24s %-8s %s"%(i.address,i.bytes.hex(),i.mnemonic,i.op_str))
