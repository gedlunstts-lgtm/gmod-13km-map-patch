import pefile,keystone,capstone,hashlib,re
SRC='engine_src.dll'; OUT='engine.dll'
pe=pefile.PE(SRC); data=bytearray(open(SRC,'rb').read()); B=0x180000000
img=pe.get_memory_mapped_image()
ks=keystone.Ks(keystone.KS_ARCH_X86,keystone.KS_MODE_64); md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
def asm(s,va): return bytes(ks.asm(s,va)[0])
def off(va): return pe.get_offset_from_rva(va-B)
def comb(dst,dst16,base): return f'movzx {dst}, word ptr [{base}+0x5c]; shl {dst},16; or {dst16}, word ptr [{base}+0x58]'
H=[ # hook, orig hex, body, back
 (0x180117eee,'410fb741086641894032','movzx eax, word ptr [r9+8]; mov word ptr [r8+0x32], ax; movzx eax, word ptr [r9+0xc]; mov word ptr [r8+0x34], ax',0x180117ef8),
 (0x1800e38aa,'0fb7435848896c2460', comb('eax','ax','rbx')+'; mov qword ptr [rsp+0x60], rbp',0x1800e38b3),
 (0x1800e414c,'0fb746583b83d8000000', comb('eax','ax','rsi')+'; cmp eax, dword ptr [rbx+0xd8]',0x1800e4156),
 (0x1800ea0f3,'410fb74d58', comb('ecx','cx','r13'),0x1800ea0f8),
 (0x180130184,'0fb743583b87d8000000', comb('eax','ax','rbx')+'; cmp eax, dword ptr [rdi+0xd8]',0x18013018e),
 (0x1800f03eb,'410fb747583b82d8000000', comb('eax','ax','r15')+'; cmp eax, dword ptr [rdx+0xd8]',0x1800f03f6),
 (0x1800f0882,'410fb746583b82d8000000', comb('eax','ax','r14')+'; cmp eax, dword ptr [rdx+0xd8]',0x1800f088d),
]
# check nobody jumps into the middle of replaced bytes
text=[s for s in pe.sections if s.Name.startswith(b'.text')][0]
inner=set()
for h,o,_,_ in H:
    for a in range(h+1,h+len(bytes.fromhex(o))): inner.add(a)
tb=img[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]
import struct
for m in re.finditer(rb'[\xe8\xe9\xeb]|[\x70-\x7f]|\x0f[\x80-\x8f]',tb):
    pass
bad=[]
funcs=sorted(set((e.struct.BeginAddress,e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION))
for b,e in funcs:
    if not any(b<=h-B<e+0x400 or h-B-0x2000<=b<=h-B+0x2000 for h,_,_,_ in H): continue
    for x in md.disasm(img[b:e],B+b):
        if x.mnemonic.startswith('j') or x.mnemonic=='call':
            try: t=int(x.op_str,16)
            except: continue
            if t in inner: bad.append((hex(x.address),hex(t)))
print('jumps into replaced bytes:',bad)
CAVE=0x180e538c0; cur=CAVE
for h,o,body,back in H:
    o=bytes.fromhex(o); assert data[off(h):off(h)+len(o)]==o,(hex(h),data[off(h):off(h)+len(o)].hex())
    code=asm(body,cur); code+=asm('jmp %#x'%back,cur+len(code))
    assert all(b==0 for b in data[off(cur):off(cur)+len(code)])
    data[off(cur):off(cur)+len(code)]=code
    j=asm('jmp %#x'%cur,h); data[off(h):off(h)+len(o)]=j+b'\x90'*(len(o)-len(j))
    for x in md.disasm(code,cur): print('  %x %s %s'%(x.address,x.mnemonic,x.op_str))
    cur=(cur+len(code)+15)&~15
assert cur<0x180e53ff0
open(OUT,'wb').write(data)
p2=pefile.PE(OUT); p2.OPTIONAL_HEADER.CheckSum=p2.generate_checksum(); p2.write(OUT)
print(hashlib.sha256(open(OUT,'rb').read()).hexdigest())
