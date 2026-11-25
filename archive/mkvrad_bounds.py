# vrad_483k: WindingBounds and ClearBounds start from +-99999, so anything
# beyond 99999 units gets a box that reaches back to 99999. SubdividePatch
# then splits patches at the middle of that box - outside the patch - and
# every split is rejected as "zero area child patch". Start from +-1e7.
import pefile,hashlib,struct,sys
SRC,OUT=sys.argv[1],sys.argv[2]
B=0x140000000
pe=pefile.PE(SRC); raw=bytearray(open(SRC,'rb').read())
off=lambda va: pe.get_offset_from_rva(va-B)
assert hashlib.sha256(raw).hexdigest()=='a473756524deaada39e20d57905ca209097ce791184d3c47c9a06cd61f0d7078'
P=0x17cfc000+B+0x80            # free space in .patch
POS,NEG=P,P+8
assert not any(raw[off(P):off(P)+16])
raw[off(POS):off(POS)+8]=struct.pack('<2f',1e7,1e7)
raw[off(NEG):off(NEG)+8]=struct.pack('<2f',-1e7,-1e7)
def imm(va,old,new):
    o=off(va); assert raw[o:o+4]==struct.pack('<f',old),(hex(va),raw[o:o+4].hex()); raw[o:o+4]=struct.pack('<f',new)
def ripdisp(insn,length,target,oldtarget):
    o=off(insn)+length-4
    cur=struct.unpack('<i',raw[o:o+4])[0]; assert insn+length+cur==oldtarget,(hex(insn),hex(insn+length+cur))
    raw[o:o+4]=struct.pack('<i',target-(insn+length))
for fn,base,r1 in [('WindingBounds',0x140057320,0x140057327),('ClearBounds',0x1400c5860,0x1400c5867)]:
    imm(base+3,99999.0,1e7)
    ripdisp(r1,8,POS,0x140149e60)
# second halves (offsets differ: r8 vs rdx encodings)
imm(0x140057337,-99999.0,-1e7); ripdisp(0x14005733b,8,NEG,0x140148760)
imm(0x1400c5876,-99999.0,-1e7); ripdisp(0x1400c587a,8,NEG,0x140148760)
open(OUT,'wb').write(raw)
print(hashlib.sha256(raw).hexdigest())
