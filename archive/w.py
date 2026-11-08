import sys,pickle; sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone.x86 import *
p=PE('engine.dll')
def scan(lo,hi,ctx=2,only16=True):
    o=p.va2o(lo); code=bytes(p.d[o:o+(hi-lo)])
    ins=list(p.md.disasm(code,lo))
    hits=[]
    for n,i in enumerate(ins):
        txt=i.op_str
        is16 = ('word ptr' in txt and 'dword' not in txt and 'qword' not in txt)
        if is16: hits.append(n)
    out=[]
    shown=set()
    for n in hits:
        for k in range(max(0,n-ctx), min(len(ins),n+ctx+1)):
            if k in shown: continue
            shown.add(k)
            i=ins[k]
            mark='>>' if k==n else '  '
            out.append(f'{mark} {i.address:x}  {i.bytes.hex():<16} {i.mnemonic} {i.op_str}')
        out.append('   ---')
    print('\n'.join(out))
if __name__=='__main__':
    lo=int(sys.argv[1],16); hi=int(sys.argv[2],16)
    ctx=int(sys.argv[3]) if len(sys.argv)>3 else 2
    scan(lo,hi,ctx)
