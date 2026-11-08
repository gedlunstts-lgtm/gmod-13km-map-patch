import sys, pickle, struct, collections
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
from capstone.x86 import *

p = PE('engine.dll')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
riprefs = collections.defaultdict(list)   # target_va -> [(ins_va, mnem)]
calls   = collections.defaultdict(list)   # target_va -> [ins_va]
sec = p.getsec('.text'); textlo = sec['va']+p.base; texthi = textlo+sec['vs']
nins=0
for (s,e) in p.funcs:
    va = s + p.base
    if not (textlo <= va < texthi): continue
    o = p.r2o(s)
    if o is None: continue
    code = bytes(p.d[o:o+(e-s)])
    for ins in md.disasm(code, va):
        nins+=1
        if ins.id in (X86_INS_CALL, X86_INS_JMP):
            for op in ins.operands:
                if op.type==X86_OP_IMM:
                    calls[op.imm].append(ins.address)
        for op in ins.operands:
            if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                riprefs[tgt].append((ins.address, ins.mnemonic))
print('instructions', nins, 'riprefs', len(riprefs), 'calltargets', len(calls))
pickle.dump((dict(riprefs), dict(calls)), open('/home/claude/eng/idx.pkl','wb'))
