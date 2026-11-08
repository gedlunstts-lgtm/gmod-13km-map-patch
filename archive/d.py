import sys, pickle
sys.path.insert(0,'/home/claude/tools')
from pe import PE
p = PE('engine.dll')
riprefs, calls = pickle.load(open('/home/claude/eng/idx.pkl','rb'))
def show(va, end=None, limit=6000):
    f = p.func_of(va)
    if end is None:
        end = f[1] if f else va+limit
    o = p.va2o(va)
    code = bytes(p.d[o:o+(end-va)])
    for ins in p.md.disasm(code, va):
        extra=''
        for op in ins.operands:
            pass
        s = f'{ins.address:012x}  {ins.bytes.hex():<22} {ins.mnemonic} {ins.op_str}'
        # annotate rip targets
        if 'rip' in ins.op_str:
            import re
            m = re.search(r'rip \+ (0x[0-9a-f]+)|rip - (0x[0-9a-f]+)', ins.op_str)
            if m:
                d = int(m.group(1),16) if m.group(1) else -int(m.group(2),16)
                t = ins.address+ins.size+d
                fo = p.va2o(t)
                sec = p.sec_of_rva(t-p.base)
                ann = f'  ; {t:x} [{sec["name"] if sec else "?"}]'
                if sec and sec['name'] in ('.rdata',) and fo:
                    raw = bytes(p.d[fo:fo+60])
                    if all(32<=c<127 or c==0 for c in raw[:20]) and raw[0]!=0:
                        ann += ' "'+raw.split(b'\0')[0].decode('ascii','replace')[:50]+'"'
                extra = ann
        print(s+extra)
if __name__=='__main__':
    va = int(sys.argv[1],16)
    end = int(sys.argv[2],16) if len(sys.argv)>2 else None
    show(va,end)
