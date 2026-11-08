import sys, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
def show(p, va, end=None, limit=400):
    f = p.func_of(va)
    if end is None:
        end = (f[1]+p.base) if f else va+limit
        end = min(end, va+limit)
    o = p.va2o(va)
    code = bytes(p.d[o:o+(end-va)])
    for ins in p.md.disasm(code, va):
        s = f'{ins.address:012x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}'
        extra=''
        if 'rip' in ins.op_str:
            m = re.search(r'rip \+ (0x[0-9a-f]+)|rip - (0x[0-9a-f]+)', ins.op_str)
            if m:
                d = int(m.group(1),16) if m.group(1) else -int(m.group(2),16)
                t = ins.address+ins.size+d
                sec = p.sec_of_rva(t-p.base)
                extra = f'  ; {t:x} [{sec["name"] if sec else "?"}]'
                fo = p.va2o(t)
                if sec and sec['name']=='.rdata' and fo:
                    raw = bytes(p.d[fo:fo+60])
                    if raw[0] and all(32<=c<127 or c==0 for c in raw[:16]):
                        extra += ' "'+raw.split(b'\0')[0].decode('ascii','replace')[:60]+'"'
        print(s+extra)
if __name__=='__main__':
    p = PE(sys.argv[1])
    va = int(sys.argv[2],16)
    end = int(sys.argv[3],16) if len(sys.argv)>3 else None
    show(p, va, end)
