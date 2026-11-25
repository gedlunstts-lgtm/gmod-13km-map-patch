# vrad_483k never fills its command-line object (vbsp and vvis do, at the
# start of main), so -game on the command line is ignored and vrad falls back
# to the VPROJECT environment variable or to guessing - "Unable to find
# gameinfo.txt" when Hammer++ is not started through HAMMER483.bat.
# Fix: at the start of ParseCommandLine, call CommandLine()->CreateCmdLine(argc, argv).
import pefile,hashlib,struct,sys,keystone,capstone
SRC,OUT=sys.argv[1],sys.argv[2]
B=0x140000000
pe=pefile.PE(SRC); raw=bytearray(open(SRC,'rb').read())
off=lambda va: pe.get_offset_from_rva(va-B)
assert hashlib.sha256(raw).hexdigest()=='b373926ff015fd4f9e427ee833f1e4abc285d6783c38d12629768a54c85c1373'
ks=keystone.Ks(keystone.KS_ARCH_X86,keystone.KS_MODE_64)
HOOK=0x14006cdd3; BACK=0x14006cddd
assert bytes(raw[off(HOOK):off(BACK)])==bytes.fromhex('4889d789cb4c89442428')
STUB=0x157cfc090
assert not any(raw[off(STUB):off(STUB)+0x40])
stub=f'''
mov rdi, rdx
mov ebx, ecx
mov qword ptr [rsp+0x28], r8
call 0x1400eff00
mov rcx, rax
mov r9, qword ptr [rax]
mov edx, ebx
mov r8, rdi
call qword ptr [r9]
mov r8, qword ptr [rsp+0x28]
jmp {hex(BACK)}
'''
enc,_=ks.asm(stub,STUB); enc=bytes(enc)
raw[off(STUB):off(STUB)+len(enc)]=enc
j,_=ks.asm(f'jmp {hex(STUB)}',HOOK); j=bytes(j)
raw[off(HOOK):off(BACK)]=j+b'\x90'*(BACK-HOOK-len(j))
open(OUT,'wb').write(raw)
print(hashlib.sha256(raw).hexdigest())
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for x in md.disasm(enc,STUB): print('%x %s %s'%(x.address,x.mnemonic,x.op_str))
for x in md.disasm(bytes(raw[off(HOOK):off(BACK)+4]),HOOK): print('%x %s %s'%(x.address,x.mnemonic,x.op_str))
