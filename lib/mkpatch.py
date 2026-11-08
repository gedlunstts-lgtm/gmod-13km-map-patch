"""GLP1 - GMod Limits Patch.
Patch soderzhit TOLKO nashi bajty: dlja kazhdoj pozicii, gde patched != original,
pishetsja nash bajt. Bajty originala v fajl ne popadajut nikogda.
Proverka versii - po SHA-256, a ne po hraneniju ishodnyh bajt.
"""
import hashlib, struct, sys, os

MAGIC=b'GLP1'

def runs(a, b):
    """Otrezki, gde b otlichaetsja ot a. Razryv v 1 bajt uzhe rvjot otrezok,
       chtoby v patch ne popal ni odin sovpadajushchij (t.e. ishodnyj) bajt."""
    n=min(len(a),len(b)); out=[]; i=0
    while i<n:
        if a[i]!=b[i]:
            j=i
            while j<n and a[j]!=b[j]: j+=1
            out.append((i, b[i:j])); i=j
        else: i+=1
    if len(b)>len(a):                      # hvost - nashi novye sekcii
        out.append((len(a), b[len(a):]))
    return out

def build(pairs, out_path, note=''):
    files=[]
    for target, src, dst in pairs:
        a=open(src,'rb').read(); b=open(dst,'rb').read()
        r=runs(a,b)
        # --- zhjostkaja proverka: nichego iz originala ---
        for off,blob in r:
            if off < len(a):
                assert all(a[off+k]!=blob[k] for k in range(len(blob))), \
                    "utechka originala v %s na %#x" % (target,off)
        files.append((target,a,b,r))
    with open(out_path,'wb') as f:
        f.write(MAGIC)
        nb=note.encode(); f.write(struct.pack('<H',len(nb))); f.write(nb)
        f.write(struct.pack('<I',len(files)))
        for target,a,b,r in files:
            tb=target.encode()
            f.write(struct.pack('<H',len(tb))); f.write(tb)
            f.write(hashlib.sha256(a).digest())
            f.write(hashlib.sha256(b).digest())
            f.write(struct.pack('<QQI',len(a),len(b),len(r)))
            for off,blob in r:
                f.write(struct.pack('<QI',off,len(blob))); f.write(blob)
    return files

def apply(patch_path, resolve):
    d=open(patch_path,'rb').read(); p=0
    assert d[:4]==MAGIC; p=4
    nl,=struct.unpack_from('<H',d,p); p+=2; note=d[p:p+nl].decode(); p+=nl
    nf,=struct.unpack_from('<I',d,p); p+=4
    res=[]
    for _ in range(nf):
        nl,=struct.unpack_from('<H',d,p); p+=2
        target=d[p:p+nl].decode(); p+=nl
        h_old=d[p:p+32]; p+=32; h_new=d[p:p+32]; p+=32
        osz,nsz,ne=struct.unpack_from('<QQI',d,p); p+=20
        path=resolve(target)
        cur=bytearray(open(path,'rb').read())
        ok = (len(cur)==osz and hashlib.sha256(cur).digest()==h_old)
        # rost - dopolnjaem nuljami, usechenie - obrezaem (u nas ono byvaet:
        # pri dobavlenii sekcii otbrasyvaetsja sertifikat Authenticode)
        buf=bytearray(cur[:nsz])+bytearray(nsz-osz if nsz>osz else 0)
        for _ in range(ne):
            off,ln=struct.unpack_from('<QI',d,p); p+=12
            buf[off:off+ln]=d[p:p+ln]; p+=ln
        good = hashlib.sha256(bytes(buf)).digest()==h_new
        res.append((target,ok,good,bytes(buf)))
    return note,res
