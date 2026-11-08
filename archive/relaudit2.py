"""Audit perenosov: sravnenie stock vs patched nadezhnym sborshchikom ssylok."""
import sys,bisect
sys.path.insert(0,'/home/claude/tools')
from pe import PE
from refs import Refs
stock,patched=sys.argv[1],sys.argv[2]
ps=PE(stock); Rs=Refs(ps)
pp=PE(patched); Rp=Refs(pp)
print("%s -> %s" % (stock.split('/')[-1],patched.split('/')[-1]))
print("  rip-ssylok: stock %d, patched %d" % (len(Rs.map),len(Rp.map)))
common=[a for a in Rs.map if a in Rp.map]
moved={}; same=[]
for a in common:
    if Rs.map[a][3]!=Rp.map[a][3]: continue
    if Rs.map[a][2]!=Rp.map[a][2]: moved[a]=(Rs.map[a][2],Rp.map[a][2])
    else: same.append(a)
print("  obshchih %d ; perenesennyh %d" % (len(common),len(moved)))
groups={}
for a,(o,n) in moved.items(): groups.setdefault(n-o,[]).append((a,o))
alladdr=sorted({v[2] for v in Rs.map.values()})
print("\n  gruppy perenosa:")
leaks=0
basemap={}
for delta,lst in sorted(groups.items(), key=lambda kv:-len(kv[1])):
    bases=sorted({o for _,o in lst})
    base=bases[0]; top=bases[-1]
    j=bisect.bisect_right(alladdr,top); nxt=alladdr[j] if j<len(alladdr) else top+1
    print("   delta %+#x : %d ssylok, bazy %012x..%012x, sled. global %012x (zapas %#x)"
          % (delta,len(lst),base,top,nxt,nxt-base))
    basemap.setdefault(base,[]).append(delta)
    bad=[a for a in same if base<=Rs.map[a][2]<nxt]
    for a in bad:
        print("      !!! UTECHKA %012x  %s -> %012x (+%d ot bazy)"
              % (a,Rp.map[a][3],Rs.map[a][2],Rs.map[a][2]-base)); leaks+=1
dbl={b:ds for b,ds in basemap.items() if len(ds)>1}
if dbl:
    print("\n  !!! BAZY S DVUMJA RAZNYMI PUNKTAMI NAZNACHENIJA:")
    for b,ds in dbl.items(): print("      %012x -> %s" % (b,[hex(x) for x in ds]))
print("\n  VSEGO UTECHEK: %d ; dvojnyh naznachenij: %d" % (leaks,len(dbl)))
