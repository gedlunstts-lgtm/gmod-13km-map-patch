"""vbsp_v12: zapis starshih bit planenum.
   dface_t.side  (+2): bit0 = planenum&1 (kak bylo), bity1-2 = planenum>>16
   dbrushside_t.bevel (+6): bit0 = bevel, bity1-2 = planenum>>16"""
import sys, struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
h=bytes.fromhex
SRC='/home/claude/vbsp/vbsp_v11.exe'; DST='/home/claude/vbsp/vbsp_v12.exe'
p=PE(SRC); d=bytearray(p.d); raw=bytes(p.d)
sec=[x for x in p.sec if x['name']=='.patch'][0]
PATCH=p.base+sec['va']; PEND=PATCH+sec['rs']
o=p.va2o(PATCH); used=len(raw[o:o+sec['rs']].rstrip(b'\x00'))
cur=PATCH+((used+15)&~15)
print("stuby s %012x do %012x"%(cur,PEND))
def wr(va,b):
    off=p.va2o(va); d[off:off+len(b)]=b
def rd(va,n):
    off=p.va2o(va); return raw[off:off+n]

# ---------- 1. EmitFace ----------
F0,F1=0x14007be5c,0x14007be75              # 25 bajt
old=rd(F0,F1-F0)
exp=h('0fb74640')+h('664389043e')+h('43886c3e03')+h('0fb64640')+h('2401')+h('4388443e02')
assert old==exp, old.hex()
stub=bytearray()
stub+=h('8b4640')            # mov eax, dword [rsi+0x40]    polnyj planenum
stub+=h('664389043e')        # mov word [r14+r15], ax        mladshie 16
stub+=h('43886c3e03')        # mov byte [r14+r15+3], bpl     onNode
stub+=h('51')                # push rcx
stub+=h('89c1')              # mov ecx, eax
stub+=h('c1e90f')            # shr ecx, 15
stub+=h('83e106')            # and ecx, 6                    bity16-17 -> 1-2
stub+=h('2401')              # and al, 1
stub+=h('08c8')              # or  al, cl
stub+=h('59')                # pop rcx
stub+=h('4388443e02')        # mov byte [r14+r15+2], al      side
stub+=h('e9')+struct.pack('<i', F1-(cur+len(stub)+5))
wr(cur,bytes(stub))
wr(F0, h('e9')+struct.pack('<i', cur-(F0+5))+h('90')*(F1-F0-5))
print("EmitFace     %012x -> stub %012x (%d bajt)"%(F0,cur,len(stub)))
cur=(cur+len(stub)+15)&~15

# ---------- 2. EmitBrushes (zapis bevel) ----------
B0,B1=0x14007d890,0x14007d8a0              # 16 bajt
old=rd(B0,B1-B0)
exp=h('4d8b5f30')+h('470fb75c0b30')+h('6646895cd206')
assert old==exp, old.hex()
stub=bytearray()
stub+=h('4d8b5f30')          # mov r11, [r15+0x30]
stub+=h('470fb75c0b30')      # movzx r11d, word [r11+r9+0x30]   bevel
stub+=h('6646895cd206')      # mov word [rdx+r10*8+6], r11w
stub+=h('4d8b5f30')          # mov r11, [r15+0x30]
stub+=h('478b1c0b')          # mov r11d, dword [r11+r9]         planenum 32 bit
stub+=h('41c1eb0f')          # shr r11d, 15
stub+=h('4183e306')          # and r11d, 6
stub+=h('6646095cd206')      # or  word [rdx+r10*8+6], r11w
stub+=h('e9')+struct.pack('<i', B1-(cur+len(stub)+5))
wr(cur,bytes(stub))
wr(B0, h('e9')+struct.pack('<i', cur-(B0+5))+h('90')*(B1-B0-5))
print("EmitBrushes  %012x -> stub %012x (%d bajt)"%(B0,cur,len(stub)))
cur=(cur+len(stub)+15)&~15
assert cur<PEND, "ne hvatilo .patch"
open(DST,'wb').write(bytes(d))
print("zapisan",DST)

# ---------- proverka ----------
q=PE(DST); md=Cs(CS_ARCH_X86,CS_MODE_64); qd=bytes(q.d)
for lbl,a,n in (('EmitFace sajt',F0,12),('EmitBrushes sajt',B0,12)):
    print("---",lbl); off=q.va2o(a)
    for i in md.disasm(qd[off:off+n],a): print("   %012x %-7s %s"%(i.address,i.mnemonic,i.op_str))
st=PATCH+((used+15)&~15)
print("--- stuby ---"); off=q.va2o(st)
for i in md.disasm(qd[off:off+(cur-st)],st):
    print("   %012x  %-20s %-7s %s"%(i.address,i.bytes.hex(),i.mnemonic,i.op_str))
