import sys,re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
p=PE(sys.argv[1]); md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
ADD=int(sys.argv[2],16); LO=int(sys.argv[3],16); HI=int(sys.argv[4],16)
o=p.va2o(LO)
ins=list(md.disasm(bytes(p.d)[o:o+(HI-LO)],LO))
def t(i):
    m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
    if not m: return None
    return i.address+i.size+int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
NAMES={0:'ENTITIES',1:'PLANES',2:'TEXDATA',3:'VERTEXES',4:'VISIBILITY',5:'NODES',6:'TEXINFO',7:'FACES',
 8:'LIGHTING',9:'OCCLUSION',10:'LEAFS',11:'FACEIDS',12:'EDGES',13:'SURFEDGES',14:'MODELS',15:'WORLDLIGHTS',
 16:'LEAFFACES',17:'LEAFBRUSHES',18:'BRUSHES',19:'BRUSHSIDES',20:'AREAS',21:'AREAPORTALS',26:'DISPINFO',
 27:'ORIGINALFACES',28:'PHYSDISP',29:'PHYSCOLLIDE',30:'VERTNORMALS',31:'VERTNORMALINDICES',
 35:'GAME_LUMP',36:'LEAFWATERDATA',39:'FACES_HDR',43:'DISP_VERTS',48:'DISP_TRIS',58:'FACES_HDR?'}
for k,i in enumerate(ins):
    if i.mnemonic!='call': continue
    ct = int(i.op_str,16) if i.op_str.startswith('0x') else t(i)
    if ct!=ADD: continue
    lump=None; arr=None; cnt=None; mul=[]
    for y in ins[max(0,k-9):k]:
        op=y.op_str.split(', ')
        if y.mnemonic=='mov' and op[0]=='ecx' and len(op)==2 and op[1].startswith('0x') and 'rip' not in y.op_str:
            lump=int(op[1],16)
        if y.mnemonic=='mov' and op[0]=='ecx' and op[1:]==['1']: lump=1
        if y.mnemonic in('lea','mov') and op[0] in('rdx',) and 'rip' in y.op_str:
            arr=(t(y), y.mnemonic)
        if 'rip' in y.op_str and op[0] in('eax','r8d') and y.mnemonic in('mov','imul'):
            cnt=t(y)
            if y.mnemonic=='imul': mul.append(op[-1])
        if y.mnemonic in('shl','add','lea','imul') and 'rip' not in y.op_str: mul.append(y.mnemonic+' '+y.op_str)
    nm=NAMES.get(lump,'?')
    print("lump %-3s %-16s arr=%s%-14s cnt=%-14s | %s" % (
        lump,nm,
        ('*' if arr and arr[1]=='mov' else ' '),
        hex(arr[0]) if arr else '?',
        hex(cnt) if cnt else '?', '; '.join(mul[-3:])))
