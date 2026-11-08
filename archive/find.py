import sys, pickle
sys.path.insert(0,'/home/claude/tools')
from pe import PE
p = PE('engine.dll')
riprefs, calls = pickle.load(open('/home/claude/eng/idx.pkl','rb'))

def strva(fileoff): return p.o2va(fileoff)

def find_str(s, enc='ascii'):
    b = s.encode(enc); out=[]; i=0
    d = bytes(p.d)
    while True:
        i = d.find(b, i)
        if i<0: break
        out.append(i); i+=1
    return out

def refs_to_str(s):
    res=[]
    for fo in find_str(s):
        va = p.o2va(fo)
        if va is None: continue
        for (ia, mn) in riprefs.get(va, []):
            f = p.func_of(ia)
            res.append((s, hex(va), hex(ia), mn, hex(f[0]) if f else None, hex(f[1]) if f else None))
    return res

if __name__=='__main__':
    for s in sys.argv[1:]:
        r = refs_to_str(s)
        if not r: print('NO REF:', s)
        for t in r: print(t)
