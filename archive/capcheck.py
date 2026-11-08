import sys, re
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from capstone import *
from capstone.x86 import *

EXE=sys.argv[1]; S=int(sys.argv[2],16); E=int(sys.argv[3],16); ADDLUMP=int(sys.argv[4],16)
P=PE(EXE); md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
d=bytes(P.d)

# все адреса, на которые есть rip-ссылки -> для вычисления зазоров
tg=set()
def fi(s,e):
    va=P.base+s; o=P.va2o(va)
    if o is None: return []
    b=bytes(d[o:o+(e-s)]); out=[]; c=0
    while c<len(b):
        g=False
        for i in md.disasm(b[c:],va+c):
            g=True; out.append(i); c=i.address-va+i.size
        if not g: c+=1
    return out
for (a,b) in P.funcs:
    for ins in fi(a,b):
        if 'rip' in ins.op_str:
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',ins.op_str)
            if m:
                dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                t=ins.address+ins.size+dd
                sec=P.sec_of_rva(t-P.base)
                if sec and sec['name'] in ('.data','.bigarr'): tg.add(t)
ks=sorted(tg)
# конец каждой секции
ends={}
for s in P.sec: ends[s['name']]=P.base+s['va']+s['vs']
def capacity(addr):
    i=ks.index(addr)
    nxt = ks[i+1] if i+1<len(ks) else None
    sec=P.sec_of_rva(addr-P.base)['name']
    lim = ends[sec]
    if nxt is not None and nxt < lim: lim = nxt
    return lim-addr

LN={1:'PLANES',2:'TEXDATA',3:'VERTEXES',4:'VISIBILITY',5:'NODES',6:'TEXINFO',7:'FACES',8:'LIGHTING',
10:'LEAFS',11:'FACEIDS',12:'EDGES',13:'SURFEDGES',14:'MODELS',15:'WORLDLIGHTS',16:'LEAFFACES',
17:'LEAFBRUSHES',18:'BRUSHES',19:'BRUSHSIDES',20:'AREAS',21:'AREAPORTALS',26:'DISPINFO',
27:'ORIGINALFACES',28:'PHYSDISP',29:'PHYSCOLLIDE',30:'VERTNORMALS',31:'VERTNORMALINDICES',
33:'DISP_VERTS',34:'DISP_LM_SAMPLE_POS',36:'LEAFWATERDATA',37:'PRIMITIVES',38:'PRIMVERTS',
39:'PRIMINDICES',41:'CLIPPORTALVERTS',42:'CUBEMAPS',43:'TEXDATA_STR_DATA',44:'TEXDATA_STR_TBL',
45:'OVERLAYS',46:'LEAFMINDISTTOWATER',47:'FACE_MACRO_TEX',48:'DISP_TRIS',50:'WATEROVERLAYS',
51:'LEAF_AMB_IDX_HDR',52:'LEAF_AMB_IDX',53:'LIGHTING_HDR',54:'WORLDLIGHTS_HDR',
55:'LEAF_AMB_LIGHT_HDR',56:'LEAF_AMB_LIGHT',58:'FACES_HDR',59:'MAP_FLAGS',60:'OVERLAY_FADES'}

ins=fi(S-P.base, E-P.base)
st={}
rows=[]
for i,x in enumerate(ins):
    ops=x.operands
    if x.mnemonic in ('mov','lea','shl','imul','add','xor') and ops and ops[0].type==X86_OP_REG:
        st[P.md.reg_name(ops[0].reg)]=x
    if x.mnemonic=='pop' and ops and ops[0].type==X86_OP_REG and i>0 and ins[i-1].mnemonic=='push':
        st[P.md.reg_name(ops[0].reg)]=ins[i-1]
    if x.mnemonic=='call' and x.op_str.startswith('0x') and int(x.op_str,16)==ADDLUMP:
        # номер лампы
        num=None
        for r in ('ecx','rcx'):
            if r in st:
                t=st[r]
                m=re.search(r'(0x[0-9a-f]+|\b\d+)$', t.op_str)
                if m: num=int(m.group(1),16) if m.group(1).startswith('0x') else int(m.group(1))
                break
        # база массива
        base=None
        if 'rdx' in st and 'rip' in st['rdx'].op_str:
            t=st['rdx']
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',t.op_str)
            if m:
                dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                base=t.address+t.size+dd
        # размер элемента
        esz=None
        if 'r8d' in st:
            e8=st['r8d'].op_str
            if 'shl' in st['r8d'].mnemonic:
                esz=1<<int(e8.split(',')[1].strip(),0)
            elif st['r8d'].mnemonic=='imul':
                m=re.search(r'(0x[0-9a-f]+|\d+)$',e8)
                if m: esz=int(m.group(1),16) if m.group(1).startswith('0x') else int(m.group(1))
            elif st['r8d'].mnemonic=='lea':
                m=re.search(r'\[(\w+) \+ (\w+)\*(\d+)\]',e8)
                if m: esz=int(m.group(3))+1
            elif st['r8d'].mnemonic=='add' and e8.split(',')[0].strip()=='r8d':
                esz=2
        rows.append((num,base,esz))
        st.pop('rdx',None); st.pop('r8d',None); st.pop('ecx',None); st.pop('rcx',None)

print(f'{"лампа":<22}{"база":>14}{"элем":>6}{"ёмкость,байт":>14}{"влезает эл-тов":>16}  секция')
for num,base,esz in rows:
    if base is None: continue
    nm=LN.get(num,f'#{num}')
    cap=capacity(base)
    sec=P.sec_of_rva(base-P.base)['name']
    n = cap//esz if esz else 0
    print(f'{nm:<22}{base:14x}{esz if esz else "?":>6}{cap:>14,}{n:>16,}  {sec}')
