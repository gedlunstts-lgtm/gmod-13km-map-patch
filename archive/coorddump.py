import sys
sys.path.insert(0,'/home/claude/tools')
from pediff import diff
from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

def dis(code, va, n=4):
    r=[]
    for i,ins in zip(range(n), md.disasm(code, va)):
        r.append('%s %s'%(ins.mnemonic, ins.op_str))
    return ' ; '.join(r)

a,b=sys.argv[1],sys.argv[2]
A,B,runs,newsec=diff(a,b)
print()
for name,va,old,new in runs:
    # kontekst: 16 bajt do i posle iz oboih
    oa=A.va2o(va); ob=B.va2o(va)
    co=bytes(A.d[oa:oa+len(old)+12]); cn=bytes(B.d[ob:ob+len(new)+12])
    print('%-8s %012x  %d bajt'%(name,va,len(old)))
    print('        bylo: %-28s  %s'%(old.hex(), dis(co,va,3)))
    print('        stalo:%-28s  %s'%(new.hex(), dis(cn,va,3)))
