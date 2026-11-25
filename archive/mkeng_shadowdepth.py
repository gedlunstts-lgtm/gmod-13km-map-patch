import pefile,shutil,hashlib,sys
SRC='/home/claude/dispfix/engine.dll'; OUT='/home/claude/shadowfix/engine.dll'
pe=pefile.PE(SRC); data=bytearray(open(SRC,'rb').read()); B=0x180000000
P=[
 # Shader_WorldShadowDepthFill / ZFill batch builder (0x1800f8950): non-prim path
 (0x1800f8a1a,'4e8d0c71','4e8d0cb1'),      # lea r9,[rcx+r14*2] -> *4
 (0x1800f8cb3,'410fb701','418b0190'),      # movzx eax,word[r9] -> mov eax,[r9]
 (0x1800f8cb7,'4983c102','4983c104'),      # add r9,2 -> 4
 (0x1800f8e3f,'410fb701','418b0190'),
 (0x1800f8f1c,'410fb74102','418b410490'),
 (0x1800f9002,'410fb701','418b0190'),
 (0x1800f90df,'410fb74102','418b410490'),
 (0x1800f91bd,'410fb74104','418b410890'),
 (0x1800f929b,'410fb74106','418b410c90'),
 (0x1800f9492,'410fb701','418b0190'),
 (0x1800f956f,'410fb74102','418b410490'),
 (0x1800f964d,'410fb74104','418b410890'),
 # 0x1800c9200 surface vertex projector (shadow/flashlight decals)
 (0x1800c9269,'4a8d1c50','4a8d1c90'),      # lea rbx,[rax+r10*2] -> *4
 (0x1800c92c2,'4c8d7304','4c8d7308'),      # lea r14,[rbx+4] -> +8
 (0x1800c92d0,'410fb746fc','418b46f890'),
 (0x1800c92e0,'410fb746fe','418b46fc90'),
 (0x1800c9304,'410fb706','418b0690'),
 (0x1800c9434,'410fb74602','418b460490'),
 (0x1800c9445,'4983c608','4983c610'),      # add r14,8 -> 16
 (0x1800c9542,'420fb70443','428b048390'),  # movzx eax,word[rbx+r8*2] -> mov eax,[rbx+r8*4]
]
for va,o,n in P:
    off=pe.get_offset_from_rva(va-B); o=bytes.fromhex(o); n=bytes.fromhex(n)
    assert len(o)==len(n),hex(va)
    assert data[off:off+len(o)]==o,(hex(va),data[off:off+len(o)].hex())
    data[off:off+len(n)]=n
open(OUT,'wb').write(data)
pe2=pefile.PE(OUT); pe2.OPTIONAL_HEADER.CheckSum=pe2.generate_checksum(); pe2.write(OUT)
print(hashlib.sha256(open(OUT,'rb').read()).hexdigest())
