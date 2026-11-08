import struct, sys
LUMPS = {0:'ENTITIES',1:'PLANES',2:'TEXDATA',3:'VERTEXES',4:'VISIBILITY',5:'NODES',6:'TEXINFO',
7:'FACES',8:'LIGHTING',9:'OCCLUSION',10:'LEAFS',11:'FACEIDS',12:'EDGES',13:'SURFEDGES',
14:'MODELS',15:'WORLDLIGHTS',16:'LEAFFACES',17:'LEAFBRUSHES',18:'BRUSHES',19:'BRUSHSIDES',
20:'AREAS',21:'AREAPORTALS',26:'DISPINFO',27:'ORIGINALFACES',28:'PHYSDISP',29:'PHYSCOLLIDE',
30:'VERTNORMALS',31:'VERTNORMALINDICES',32:'DISP_LIGHTMAP_ALPHAS',33:'DISP_VERTS',
34:'DISP_LIGHTMAP_SAMPLE_POSITIONS',35:'GAME_LUMP',36:'LEAFWATERDATA',37:'PRIMITIVES',
38:'PRIMVERTS',39:'PRIMINDICES',40:'PAKFILE',41:'CLIPPORTALVERTS',42:'CUBEMAPS',
43:'TEXDATA_STRING_DATA',44:'TEXDATA_STRING_TABLE',45:'OVERLAYS',46:'LEAFMINDISTTOWATER',
47:'FACE_MACRO_TEXTURE_INFO',48:'DISP_TRIS',49:'PHYSCOLLIDESURFACE',50:'WATEROVERLAYS',
51:'LEAF_AMBIENT_INDEX_HDR',52:'LEAF_AMBIENT_INDEX',53:'LIGHTING_HDR',54:'WORLDLIGHTS_HDR',
55:'LEAF_AMBIENT_LIGHTING_HDR',56:'LEAF_AMBIENT_LIGHTING',57:'XZIPPAKFILE',58:'FACES_HDR',
59:'MAP_FLAGS',60:'OVERLAY_FADES',61:'OVERLAY_SYSTEM_LEVELS',62:'PHYSLEVEL',63:'DISP_MULTIBLEND'}
ELEMSZ = {1:20,3:12,5:32,6:72,7:56,10:32,12:4,13:4,14:48,16:2,17:2,18:12,19:8,20:8,21:12,
          27:56,58:56,30:12,31:2,33:20,36:10,37:10,38:12,39:2}
class BSP:
    def __init__(self, path):
        self.d = bytearray(open(path,'rb').read())
        ident, self.version = struct.unpack_from('<4si', self.d, 0)
        assert ident == b'VBSP', ident
        self.lumps=[]
        for i in range(64):
            off,ln,ver,fourcc = struct.unpack_from('<iii4s', self.d, 8+i*16)
            self.lumps.append(dict(i=i,off=off,len=ln,ver=ver,fourcc=fourcc))
        self.revision = struct.unpack_from('<i', self.d, 8+64*16)[0]
    def data(self,i):
        L=self.lumps[i]; return bytes(self.d[L['off']:L['off']+L['len']])
    def count(self,i):
        es=ELEMSZ.get(i)
        return None if not es else self.lumps[i]['len']//es
    def report(self):
        print(f'VBSP version {self.version}  revision {self.revision}  size {len(self.d)}')
        print(f"{'#':>3} {'lump':34} {'offset':>10} {'len':>10} {'ver':>3} {'count':>9}")
        for L in self.lumps:
            if L['len']==0 and L['off']==0: continue
            c=self.count(L['i'])
            print(f"{L['i']:3} {LUMPS.get(L['i'],'?'):34} {L['off']:10} {L['len']:10} {L['ver']:3} {('' if c is None else c):>9}")
if __name__=='__main__':
    BSP(sys.argv[1]).report()
