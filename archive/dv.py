import sys
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
import re
P = PE('/home/claude/vbsp/vvis_v04.exe')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
def show(va, end):
    o=P.va2o(va); buf=bytes(P.d[o:o+(end-va)]); cur=0
    while cur < len(buf):
        got=False
        for ins in md.disasm(buf[cur:], va+cur):
            got=True
            ann=''
            if 'rip' in ins.op_str:
                m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
                if m:
                    d=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                    t=ins.address+ins.size+d
                    s=P.sec_of_rva(t-P.base)
                    ann=f'   ; {t:x} [{s["name"] if s else "?"}]'
                    if s and s['name']=='.rdata':
                        fo=P.va2o(t)
                        raw=bytes(P.d[fo:fo+48])
                        if raw[0]>=32 and all(32<=c<127 or c==0 for c in raw[:16]):
                            ann+=' "'+raw.split(b'\0')[0].decode('ascii','replace')[:40]+'"'
            print(f'{ins.address:012x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{ann}')
            cur=ins.address-va+ins.size
        if not got: cur+=1
if __name__=='__main__':
    show(int(sys.argv[1],16), int(sys.argv[2],16))
