import pefile,keystone,capstone,hashlib
SRC='vbsp_src.exe'; OUT='vbsp_483k.exe'
pe=pefile.PE(SRC); data=bytearray(open(SRC,'rb').read()); B=pe.OPTIONAL_HEADER.ImageBase
ks=keystone.Ks(keystone.KS_ARCH_X86,keystone.KS_MODE_64); md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
def asm(s,va): return bytes(ks.asm(s,va)[0])
def off(va): return pe.get_offset_from_rva(va-B)
NUMFACES=0x151026d50
HOOK=0x14007c295; BACK=0x14007c2a2
orig=bytes.fromhex('0fb705b4aafa10'+'664189442418')
assert data[off(HOOK):off(HOOK)+13]==orig, data[off(HOOK):off(HOOK)+13].hex()
ST=0x169b49070
# keystone rip-relative: write absolute via computed displacement
code=b''
def emit(s):
    global code
    code+=asm(s,ST+len(code))
import struct
code+=b'\x8b\x05'+struct.pack('<i',NUMFACES-(ST+6))
emit('mov word ptr [r12+0x18], ax')
emit('mov ecx, eax'); emit('shr ecx, 16'); emit('mov word ptr [r12+0x1e], cx')
emit('movzx eax, ax'); emit('jmp %#x'%BACK)
for x in md.disasm(code,ST): print('  %x %s %s'%(x.address,x.mnemonic,x.op_str))
o=off(ST); assert all(b==0 for b in data[o:o+len(code)])
data[o:o+len(code)]=code
j=asm('jmp %#x'%ST,HOOK); data[off(HOOK):off(HOOK)+13]=j+b'\x90'*(13-len(j))
open(OUT,'wb').write(data)
p2=pefile.PE(OUT); p2.OPTIONAL_HEADER.CheckSum=p2.generate_checksum(); p2.write(OUT)
print(hashlib.sha256(open(OUT,'rb').read()).hexdigest())
