import sys, pickle, collections
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
from capstone.x86 import *
p = PE(sys.argv[1])
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
riprefs = collections.defaultdict(list); calls = collections.defaultdict(list)
sec = p.getsec('.text'); lo = sec['va']+p.base; hi = lo+sec['vs']
n=0
for (s,e) in p.funcs:
    va = s + p.base
    if not (lo <= va < hi): continue
    o = p.r2o(s)
    if o is None: continue
    for ins in md.disasm(bytes(p.d[o:o+(e-s)]), va):
        n+=1
        if ins.id in (X86_INS_CALL, X86_INS_JMP):
            for op in ins.operands:
                if op.type==X86_OP_IMM: calls[op.imm].append(ins.address)
        for op in ins.operands:
            if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                riprefs[ins.address + ins.size + op.mem.disp].append((ins.address, ins.mnemonic))
print('инструкций',n,'riprefs',len(riprefs))
pickle.dump((dict(riprefs), dict(calls)), open(sys.argv[2],'wb'))
