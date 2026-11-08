"""vbsp_v10: MAX_MAP_PLANES 65536 -> 262144 (vnutrennij mapplanes v CMapFile).
   Massiv plane_t lezhit v nachale objekta, poetomu vse polja posle nego
   sdvigajutsja na +0x600000. Vse smeshchenija uzhe disp32/imm32 -> pravka na meste."""
import sys, struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *

SRC='/home/claude/vbsp/vbsp_v09.exe'; DST='/home/claude/vbsp/vbsp_v10.exe'
SHIFT=0x600000
OLDCAP=0x200000          # 65536*32
SIZEOF=0xd9012e8
MEMSET={0x140103340,0x1401042f0}   # memset / memcpy
CODE_HI=0x140080000

p=PE(SRC); d=bytearray(p.d); md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
raw=bytes(p.d)

# 1) sobiraem funkcii CMapFile = te, gde est disp >= 0x200000
funcs={}
for s,e in p.funcs:
    va=p.base+s; o=p.va2o(va)
    if o is None or va>=CODE_HI: continue
    ins=list(md.disasm(raw[o:o+min(e-s,0x20000)],va))
    funcs[va]=ins
isCMap=set()
for va,ins in funcs.items():
    for i in ins:
        for op in i.operands:
            if op.type==3 and op.mem.disp>=OLDCAP and op.mem.base!=0 and i.reg_name(op.mem.base) not in('rsp','rbp','rip'):
                isCMap.add(va)
print("funkcij, rabotajushchih s CMapFile:",len(isCMap))

edits=[]; skipped=[]
def memset_size(ins,k):
    """mov r8d, imm neposredstvenno pered call memset -> eto dlina"""
    for y in ins[k+1:k+5]:
        if y.mnemonic=='call' and y.op_str.startswith('0x') and int(y.op_str,16) in MEMSET: return True
    return False

for va,ins in funcs.items():
    for k,i in enumerate(ins):
        o=p.va2o(i.address)
        # --- displacement ---
        for op in i.operands:
            if op.type==3 and op.mem.disp>=OLDCAP and op.mem.base!=0 and i.reg_name(op.mem.base) not in('rsp','rbp','rip'):
                e=i.encoding
                off=o+e.disp_offset
                if struct.unpack_from('<i',raw,off)[0]!=op.mem.disp:
                    raise SystemExit("disp ne disp32 na %x: %s"%(i.address,i.op_str))
                edits.append((off,op.mem.disp,op.mem.disp+SHIFT,i.address,'disp',i.mnemonic+' '+i.op_str))
        # --- immediate ---
        if va not in isCMap: continue
        if i.mnemonic in ('test','jmp','call') or i.mnemonic.startswith('j'): continue
        for op in i.operands:
            if op.type!=2 or not(OLDCAP<=op.imm<=SIZEOF): continue
            if i.operands[0].type==3:
                skipped.append((i.address,'zapis v pamjat',i.mnemonic+' '+i.op_str)); continue
            if 'rsp' in i.op_str or 'rip' in i.op_str: continue
            # razmer memset?
            if i.mnemonic=='mov' and op.imm!=0x200004 and memset_size(ins,k):
                skipped.append((i.address,'razmer memset',i.mnemonic+' '+i.op_str)); continue
            if i.mnemonic=='mov' and op.imm==0x200004 and memset_size(ins,k):
                new=0x800004
            elif i.mnemonic in ('add','cmp','sub','lea','mov'):
                new=op.imm+SHIFT
            else:
                skipped.append((i.address,'neponjatno',i.mnemonic+' '+i.op_str)); continue
            e=i.encoding
            off=o+e.imm_offset
            if struct.unpack_from('<I',raw,off)[0]!=op.imm:
                raise SystemExit("imm ne imm32 na %x: %s"%(i.address,i.op_str))
            edits.append((off,op.imm,new,i.address,'imm',i.mnemonic+' '+i.op_str))

# ubiraem dubli (odna instrukcija = odna pravka)
seen=set(); uniq=[]
for e in edits:
    if e[0] in seen: continue
    seen.add(e[0]); uniq.append(e)
print("pravok: %d (disp %d, imm %d)" % (len(uniq),
      sum(1 for e in uniq if e[4]=='disp'), sum(1 for e in uniq if e[4]=='imm')))
print("propushcheno:",len(skipped))
for a,r,t in skipped: print("    %012x  %-14s %s"%(a,r,t))
print("--- imm-pravki ---")
for off,old,new,ia,kind,txt in sorted(uniq,key=lambda x:x[3]):
    if kind=='imm': print("    %012x  0x%-9x -> 0x%-9x  %s"%(ia,old,new,txt))

# --- 3) sam predel: cmp rax, 0xffff -> 0x3ffff ---
CHK=0x1400575da
o=p.va2o(CHK)
assert raw[o:o+6]==bytes.fromhex('483dffff0000'), raw[o:o+6].hex()
uniq.append((o+2,0xffff,0x3ffff,CHK,'limit','cmp rax, 0xffff'))

for off,old,new,ia,kind,txt in uniq:
    struct.pack_into('<I',d,off,new & 0xffffffff)
open(DST,'wb').write(bytes(d))
print()
print("zapisan",DST,"pravok",len(uniq))

# --- proverka: ne ostalos li staryh smeshchenij ---
q=PE(DST); mq=Cs(CS_ARCH_X86,CS_MODE_64); mq.detail=True
rq=bytes(q.d); left=0; new=0
for s2,e2 in q.funcs:
    va=q.base+s2; o2=q.va2o(va)
    if o2 is None or va>=CODE_HI: continue
    for i in mq.disasm(rq[o2:o2+min(e2-s2,0x20000)],va):
        for op in i.operands:
            if op.type==3 and op.mem.base!=0 and i.reg_name(op.mem.base) not in('rsp','rbp','rip'):
                if OLDCAP<=op.mem.disp<OLDCAP+SHIFT: left+=1
                elif op.mem.disp>=OLDCAP+SHIFT: new+=1
print("ostalos disp v starom diapazone [0x200000,0x800000):",left)
print("disp v novom diapazone (>=0x800000):",new)
