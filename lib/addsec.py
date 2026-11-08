"""Dobavit sekciju v konec PE. Sertifikat Authenticode otbrasyvaetsja
(on vsjo ravno stanovitsja nedejstvitelnym posle pravki kodа)."""
import struct

CODE=0x60000020   # code, execute, read
DATA=0xC0000040   # initialized data, read, write

def align(v,a): return (v+a-1)//a*a

def addsec(data, specs):
    """specs = [(name, vsize, characteristics, payload_bytes_or_None), ...]
       Vozvrashchaet (novyj bytearray, {name: (va_rva, raw_off, rs)})."""
    d=bytearray(data)
    pe,=struct.unpack_from('<I',d,0x3c)
    nsec,=struct.unpack_from('<H',d,pe+6)
    optsz,=struct.unpack_from('<H',d,pe+20)
    opt=pe+24
    salign,=struct.unpack_from('<I',d,opt+0x20)
    falign,=struct.unpack_from('<I',d,opt+0x24)
    szimg,=struct.unpack_from('<I',d,opt+0x38)
    szhdr,=struct.unpack_from('<I',d,opt+0x3c)
    tbl=opt+optsz
    # mesto pod novye zapisi v tablice?
    need=tbl+40*(nsec+len(specs))
    assert need<=szhdr, 'tablice sekcij ne hvataet mesta: nuzhno %x, SizeOfHeaders %x'%(need,szhdr)
    # konec raw poslednej sekcii
    endraw=0
    for i in range(nsec):
        o=tbl+i*40
        rs,pr=struct.unpack_from('<II',d,o+16)
        endraw=max(endraw,pr+rs)
    # otbrosit sertifikat
    cdir=opt+0x70+4*8
    co,cl=struct.unpack_from('<II',d,cdir)
    if cl:
        struct.pack_into('<II',d,cdir,0,0)
    del d[endraw:]
    out={}
    va=align(szimg,salign)
    raw=align(len(d),falign)
    d+=b'\0'*(raw-len(d))
    for i,(name,vsize,ch,payload) in enumerate(specs):
        vs=align(vsize,salign)
        rs=align(vsize,falign)
        o=tbl+(nsec+i)*40
        nb=name.encode(); assert len(nb)<=8
        d[o:o+40]=b'\0'*40
        d[o:o+len(nb)]=nb
        struct.pack_into('<IIII',d,o+8, vsize, va, rs, raw)
        struct.pack_into('<I',d,o+36, ch)
        blob=bytearray(b'\0'*rs)
        if payload: blob[:len(payload)]=payload
        d+=bytes(blob)
        out[name]=(va,raw,rs)
        va+=vs; raw+=rs
    struct.pack_into('<H',d,pe+6, nsec+len(specs))
    struct.pack_into('<I',d,opt+0x38, align(va,salign))
    struct.pack_into('<I',d,opt+0x40, 0)      # CheckSum
    return d,out
