import sys
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
from capstone.x86 import *
import re
P = PE(sys.argv[1] if len(sys.argv)>1 else '/home/claude/fz/engine_fz.dll')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True

def func_ins(s,e):
    va=P.base+s; o=P.va2o(va)
    buf=bytes(P.d[o:o+(e-s)]); out=[]; cur=0
    while cur<len(buf):
        got=False
        for ins in md.disasm(buf[cur:], va+cur):
            got=True; out.append(ins); cur=ins.address-va+ins.size
        if not got: cur+=1
    return out

def reg64(r):
    n = P.md.reg_name(r) if r else None
    return n

results=[]
for (s,e) in P.funcs:
    ins = func_ins(s,e)
    # find 0x108 qword loads
    seeds=[]
    for i,x in enumerate(ins):
        if x.mnemonic=='mov' and len(x.operands)==2:
            d,sr = x.operands
            if d.type==X86_OP_REG and sr.type==X86_OP_MEM and sr.size==8 and sr.mem.disp==0x108 and sr.mem.index==0:
                bn = P.md.reg_name(sr.mem.base) if sr.mem.base else ''
                if bn not in ('rsp','rip'):
                    seeds.append((i, P.md.reg_name(d.reg)))
    if not seeds: continue
    for (si, sreg) in seeds:
        taint={sreg}
        uses=[]
        for x in ins[si+1:si+400]:
            # kill on overwrite
            ops=x.operands
            # record memory uses
            for op in ops:
                if op.type==X86_OP_MEM:
                    bn=P.md.reg_name(op.mem.base) if op.mem.base else ''
                    ix=P.md.reg_name(op.mem.index) if op.mem.index else ''
                    if bn in taint or ix in taint:
                        uses.append((x.address, x.mnemonic+' '+x.op_str, op.mem.scale, op.size))
            # propagate
            if x.mnemonic in ('mov','lea') and len(ops)==2 and ops[0].type==X86_OP_REG:
                dn=P.md.reg_name(ops[0].reg)
                src=ops[1]
                prop=False
                if src.type==X86_OP_REG and P.md.reg_name(src.reg) in taint: prop=True
                if x.mnemonic=='lea' and src.type==X86_OP_MEM:
                    bn=P.md.reg_name(src.mem.base) if src.mem.base else ''
                    ix=P.md.reg_name(src.mem.index) if src.mem.index else ''
                    if bn in taint or ix in taint: prop=True
                if prop: taint.add(dn)
                elif dn in taint and x.mnemonic=='mov': taint.discard(dn)
            elif x.mnemonic=='add' and len(ops)==2 and ops[0].type==X86_OP_REG and ops[1].type==X86_OP_REG:
                if P.md.reg_name(ops[1].reg) in taint: taint.add(P.md.reg_name(ops[0].reg))
            elif len(ops)>=1 and ops[0].type==X86_OP_REG and x.mnemonic in ('xor','pop','movzx','movsxd','sub','and','or','imul','shl','call'):
                dn=P.md.reg_name(ops[0].reg)
                if dn in taint and x.mnemonic!='call': taint.discard(dn)
            if x.mnemonic=='call':
                for r in ['rax','rcx','rdx','r8','r9','r10','r11']:
                    taint.discard(r)
            if x.mnemonic=='ret': break
        if uses:
            results.append((P.base+s, P.base+ins[si].address-P.base if False else ins[si].address, sreg, uses))

for f,seed,reg,uses in results:
    sc = set(u[2] for u in uses)
    print(f'FUNC {f:012x}  seed {seed:012x} -> {reg}  scales={sorted(sc)}')
    for a,txt,scale,size in uses[:12]:
        print(f'    {a:012x}  {txt}   (scale {scale}, opsize {size})')
