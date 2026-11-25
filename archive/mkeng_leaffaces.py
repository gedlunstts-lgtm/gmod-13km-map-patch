# firstmarksurface (mleaf +0x44 low / +0x4a high): 4 chitatelja, kotorye propustili
import pefile,keystone,capstone,hashlib,struct
SRC='/home/claude/shadowfix/engine.dll'; OUT='/home/claude/leaffix/engine.dll'
pe=pefile.PE(SRC); data=bytearray(open(SRC,'rb').read()); B=0x180000000
ks=keystone.Ks(keystone.KS_ARCH_X86,keystone.KS_MODE_64)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
def asm(s,va): return bytes(ks.asm(s,va)[0])
def put(va,old,new):
    o=pe.get_offset_from_rva(va-B); old=bytes.fromhex(old) if isinstance(old,str) else old
    assert len(old)==len(new),(hex(va),old.hex(),new.hex())
    assert data[o:o+len(old)]==old,(hex(va),data[o:o+len(old)].hex(),old.hex())
    data[o:o+len(new)]=new
CAVE=0x180e53800; cur=CAVE
S=[ # (hook va, original bytes, stub body, back)
 (0x1800ef6b2,'410fb75744', 'movzx edx, word ptr [r15+0x4a]; shl edx,16; or dx, word ptr [r15+0x44]', 0x1800ef6b7),
 (0x1800ef992,'450fb74544', 'movzx r8d, word ptr [r13+0x4a]; shl r8d,16; or r8w, word ptr [r13+0x44]', 0x1800ef997),
 (0x18012f931,'440fb74944', 'movzx r9d, word ptr [rcx+0x4a]; shl r9d,16; or r9w, word ptr [rcx+0x44]', 0x18012f936),
 # Mod_LoadMarksurfaces: perepakovka spiskov listev (chtenie i zapis firstmarksurface)
 (0x180117c70,'410fb748fe03c8', 'movzx ecx, word ptr [r8+4]; shl ecx,16; or cx, word ptr [r8-2]; add ecx, eax', 0x180117c77),
 (0x180117cac,'664189 68fe'.replace(' ',''), 'mov word ptr [r8-2], bp; mov edx, ebp; shr edx,16; mov word ptr [r8+4], dx', 0x180117cb1),
 (0x18011542c,'0fb753444889742430', 'mov qword ptr [rsp+0x30], rsi; pushfq; movzx edx, word ptr [rbx+0x4a]; shl edx,16; or dx, word ptr [rbx+0x44]; popfq', 0x180115435),
]
for hook,orig,body,back in S:
    va=cur
    code=asm(body,va); code+=asm('jmp %#x'%back, va+len(code))
    o=pe.get_offset_from_rva(va-B); assert all(x==0 for x in data[o:o+len(code)])
    data[o:o+len(code)]=code
    j=asm('jmp %#x'%va, hook); n=len(bytes.fromhex(orig)); assert len(j)==5
    put(hook,orig,j+b'\x90'*(n-5))
    for x in md.disasm(code,va): print('  %x %s %s'%(x.address,x.mnemonic,x.op_str))
    cur=(va+len(code)+15)&~15
assert cur<0x180e53ff0
open(OUT,'wb').write(data)
pe2=pefile.PE(OUT); pe2.OPTIONAL_HEADER.CheckSum=pe2.generate_checksum(); pe2.write(OUT)
print(hashlib.sha256(open(OUT,'rb').read()).hexdigest())
