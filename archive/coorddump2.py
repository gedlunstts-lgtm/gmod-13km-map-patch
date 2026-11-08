import sys, bisect
sys.path.insert(0,'/home/claude/tools')
from pediff import diff

def ins_at(P, va):
    """Instrukcija, soderzhashchaja va: disassembliruem s nachala funkcii."""
    rva=va-P.base
    i=bisect.bisect_right(P.fstarts,rva)-1
    if i<0: return None
    s,e=P.funcs[i]
    if not (s<=rva<e): return None
    code=P.read(s+P.base, e-s)
    prev=None
    for ins in P.md.disasm(code, s+P.base):
        if ins.address<=va<ins.address+ins.size: return ins
        if ins.address>va: return None
    return None

a,b=sys.argv[1],sys.argv[2]
A,B,runs,newsec=diff(a,b)
print()
seen=set()
for name,va,old,new in runs:
    ia=ins_at(A,va); ib=ins_at(B,va)
    if ia is None:
        print('%-7s %012x %2db  %s -> %s   (ne v .pdata / ne kod)'%(name,va,len(old),old.hex(),new.hex()))
        continue
    if ia.address in seen: continue
    seen.add(ia.address)
    print('%-7s %012x %2db'%(name,va,len(old)))
    print('          %012x  %-22s %s %s'%(ia.address, ia.bytes.hex(), ia.mnemonic, ia.op_str))
    print('       -> %012x  %-22s %s %s'%(ib.address, ib.bytes.hex(), ib.mnemonic, ib.op_str))
