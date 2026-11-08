import sys, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
from capstone.x86 import *
P = PE('/home/claude/vbsp/vbsp_v02.exe')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
GETVERT = 0x140049040           # GetVertexnum -> eax
DEDGES  = 0x162cbf000

def func_ins(s,e):
    va=P.base+s; o=P.va2o(va)
    if o is None: return []
    buf=bytes(P.d[o:o+(e-s)]); out=[]; cur=0
    while cur<len(buf):
        got=False
        for ins in md.disasm(buf[cur:], va+cur):
            got=True; out.append(ins); cur=ins.address-va+ins.size
        if not got: cur+=1
    return out

def rn(r): return P.md.reg_name(r) if r else ''
def fam(n):
    m={'eax':'rax','ecx':'rcx','edx':'rdx','ebx':'rbx','esi':'rsi','edi':'rdi','ebp':'rbp','esp':'rsp'}
    if n in m: return m[n]
    if n and n.startswith('r') and n.endswith('d'): return n[:-1]
    return n

hits={}
for (s,e) in P.funcs:
    ins=func_ins(s,e)
    seeds=[]
    for i,x in enumerate(ins):
        if x.mnemonic=='call' and x.op_str.startswith('0x') and int(x.op_str,16)==GETVERT:
            seeds.append((i,'rax'))
    if not seeds: continue
    for si,sreg in seeds:
        taint={sreg}
        for x in ins[si+1:si+250]:
            ops=x.operands
            for op in ops:
                if op.type==X86_OP_MEM:
                    b=fam(rn(op.mem.base)); ix=fam(rn(op.mem.index))
                    if ix in taint and op.mem.base:
                        hits.setdefault(('idxreg',), []).append((x.address, x.mnemonic+' '+x.op_str))
                    elif ix in taint:
                        hits.setdefault(('idxrip',), []).append((x.address, x.mnemonic+' '+x.op_str))
            # propagate
            if x.mnemonic in ('mov','movsxd','movzx','lea') and len(ops)==2 and ops[0].type==X86_OP_REG:
                dn=fam(rn(ops[0].reg)); src=ops[1]; prop=False
                if src.type==X86_OP_REG and fam(rn(src.reg)) in taint: prop=True
                if src.type==X86_OP_MEM and x.mnemonic=='lea':
                    if fam(rn(src.mem.base)) in taint or fam(rn(src.mem.index)) in taint: prop=True
                if prop: taint.add(dn)
                elif dn in taint: taint.discard(dn)
            elif x.mnemonic in ('shl','add','imul') and ops and ops[0].type==X86_OP_REG:
                pass
            elif x.mnemonic=='call':
                for r in ('rax','rcx','rdx','r8','r9','r10','r11'): taint.discard(r)
            if x.mnemonic=='ret': break
print("--- memory ops indexed by a vertex number ---")
seen=set()
for k,v in hits.items():
    for a,t in v:
        if (a,t) in seen: continue
        seen.add((a,t))
        print(f'  {a:012x}  {t}')
