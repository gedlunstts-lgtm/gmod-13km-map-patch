import sys
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
import re
P = PE(sys.argv[3])
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
va=int(sys.argv[1],16); end=int(sys.argv[2],16)
o=P.va2o(va); buf=bytes(P.d[o:o+(end-va)]); cur=0
while cur<len(buf):
    got=False
    for ins in md.disasm(buf[cur:], va+cur):
        got=True; ann=''
        if 'rip' in ins.op_str:
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
            if m:
                d=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                t=ins.address+ins.size+d
                s=P.sec_of_rva(t-P.base)
                ann=f'   ; {t:x} [{s["name"] if s else "?"}]'
        print(f'{ins.address:012x}  {ins.bytes.hex():<18} {ins.mnemonic} {ins.op_str}{ann}')
        cur=ins.address-va+ins.size
    if not got: cur+=1
