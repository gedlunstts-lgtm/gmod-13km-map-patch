import sys, struct, re, hashlib
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
SRC='/home/claude/vbsp/vbsp_v06.exe'
DST='/home/claude/vbsp/vbsp_v07.exe'
P=PE(SRC); d=bytearray(P.d)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
# staraja baza -> novaja baza, i razmer starogo diapazona
REL=[('dfaces',     0x151026d60, 0x167049000, 65536*56),
     ('dfaces_hdr', 0x1513a6d90, 0x167e49000, 65536*56),
     ('dorigfaces', 0x150b76d20, 0x168c49000, 65536*56),
     ('dleaffaces', 0x151820db0, 0x169a49000, 65536*2)]
t=P.getsec('.text'); TA=P.base+t['va']
code=bytes(d[t['raw']:t['raw']+t['vs']])
fixed=0; seen=set()
print("ishchu ostavshiesja ssylki vnutr starych diapazonov (ne tolko na bazu):\n")
for start in range(0,len(code),4096):
    for ins in md.disasm(code[start:start+4200], TA+start):
        if ins.address in seen: continue
        seen.add(ins.address)
        if 'rip' not in ins.op_str: continue
        e=ins.encoding
        if not e.disp_size: continue
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
        if not m: continue
        dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
        tg=ins.address+ins.size+dd
        for nm,ob,nb,sz in REL:
            if not (ob<=tg<ob+sz): continue
            off=tg-ob
            nt=nb+off
            nd=nt-(ins.address+ins.size)
            assert -2**31<=nd<2**31, (nm,hex(ins.address))
            fo=P.va2o(ins.address)+e.disp_offset
            assert struct.unpack_from('<i',d,fo)[0]==dd
            struct.pack_into('<i',d,fo,nd); fixed+=1
            print("  %012x  %-22s %s %s" % (ins.address,ins.bytes.hex(),ins.mnemonic,ins.op_str))
            print("        %s +%d : %012x -> %012x\n" % (nm,off,tg,nt))
print("ispravleno ssylok: %d" % fixed)
open(DST,'wb').write(bytes(d))
print("\n%s\nMD5 %s" % (DST,hashlib.md5(bytes(d)).hexdigest()))
