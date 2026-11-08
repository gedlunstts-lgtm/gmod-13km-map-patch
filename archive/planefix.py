"""Dobavljaet starshie bity planenum pri chtenii iz dface_t / dbrushside_t.
   dface_t:      side  (+2, bajt)  bity1-2
   dbrushside_t: bevel (+6, slovo) bity1-2
   planenum = word[mem] | ((high>>1 & 3) << 16)"""
import sys, struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
from keystone import *
ks=Ks(KS_ARCH_X86,KS_MODE_64)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
POOL=['rax','rcx','rdx','rbx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15']
L32={'rax':'eax','rcx':'ecx','rdx':'edx','rbx':'ebx','rsi':'esi','rdi':'edi'}
def l32(r): return L32.get(r, r+'d')

def build(src,dst,sites,extra=()):
    p=PE(src); d=bytearray(p.d); raw=bytes(p.d)
    sec=[x for x in p.sec if x['name']=='.patch'][0]
    PA=p.base+sec['va']; PEND=PA+sec['rs']
    o=p.va2o(PA); used=len(raw[o:o+sec['rs']].rstrip(b'\x00'))
    cur=PA+((used+15)&~15); start=cur
    print("=== %s -> %s   .patch svobodno s %012x"%(src.split('/')[-1],dst.split('/')[-1],cur))
    for va,kind in sites:
        off=p.va2o(va)
        i=next(md.disasm(raw[off:off+8],va))
        assert i.mnemonic=='movzx' and 'word ptr' in i.op_str, i.op_str
        dest=i.op_str.split(',')[0].strip()
        mem=i.op_str.split('[',1)[1].rstrip(']')
        used_regs={dest}|{t.strip() for t in mem.replace('+',' ').replace('*',' ').split()}
        used_regs|={('r'+dest[1:]) if dest.startswith('e') else dest.rstrip('d')}
        tmp=next(r for r in POOL if r not in used_regs and l32(r) not in used_regs)
        t32=l32(tmp)
        hi = "byte ptr [%s + 2]"%mem if kind=='face' else "word ptr [%s + 6]"%mem
        asm=("push %s; movzx %s, %s; shr %s, 1; and %s, 3; shl %s, 16; %s %s; or %s, %s; pop %s"
             %(tmp, t32, hi, t32, t32, t32, i.mnemonic, i.op_str, dest, t32, tmp))
        body=bytes(ks.asm(asm.encode())[0])
        back=va+i.size
        body+=bytes(ks.asm(b'nop')[0])*0
        body+=b'\xe9'+struct.pack('<i', back-(cur+len(body)+5))
        assert cur+len(body)<PEND, "ne hvatilo .patch"
        d[p.va2o(cur):p.va2o(cur)+len(body)]=body
        # v sajt: jmp rel32 (5) + nop do konca; nuzhno >=5 bajt
        assert i.size>=5 or True
        if i.size<5:
            # rasshirjaem zahvat na sledujushchie instrukcii
            j=next(md.disasm(raw[off:off+16],va)); tot=0; seq=[]
            for x in md.disasm(raw[off:off+24],va):
                seq.append(x); tot+=x.size
                if tot>=5: break
            # perestraivaem: stub dolzhen vypolnit i hvostovye instrukcii
            tail=b''.join(x.bytes for x in seq[1:])
            body=body[:-5]+tail+b'\xe9'+struct.pack('<i',(va+tot)-(cur+len(body)-5+len(tail)+5))
            d[p.va2o(cur):p.va2o(cur)+len(body)]=body
            back=va+tot
        n=back-va
        d[off:off+n]=b'\xe9'+struct.pack('<i',cur-(va+5))+b'\x90'*(n-5)
        print("   %012x %-9s dest=%-4s tmp=%-4s -> %012x (%d B)"%(va,kind,dest,tmp,cur,len(body)))
        cur=(cur+len(body)+15)&~15
    for va,oldhex,newasm,note in extra:
        off=p.va2o(va); old=bytes.fromhex(oldhex)
        assert raw[off:off+len(old)]==old, "%012x: %s != %s"%(va,raw[off:off+len(old)].hex(),oldhex)
        nb=bytes(ks.asm(newasm.encode(),va)[0])
        assert len(nb)<=len(old), "%s dlinnee"%newasm
        d[off:off+len(old)]=nb+b'\x90'*(len(old)-len(nb))
        print("   %012x %-9s %s   (%s)"%(va,'pravka',newasm,note))
    open(dst,'wb').write(bytes(d))
    print("   zapisan, stuby %012x..%012x"%(start,cur))
    return start,cur

if __name__=='__main__':
    pass
