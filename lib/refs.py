"""Nadezhnyj sbor rip-ssylok: razbor ot nachala kazhdoj funkcii .pdata,
   plus linejnyj prohod, plus sverka gruboj siloj."""
import struct,re,bisect
from capstone import *

class Refs:
    def __init__(self, pe):
        self.p=pe; self.d=bytes(pe.d)
        self.md=Cs(CS_ARCH_X86,CS_MODE_64); self.md.detail=True
        t=pe.getsec('.text')
        self.TA=pe.base+t['va']; self.RAW=t['raw']; self.N=t['vs']
        self.map={}          # va instrukcii -> (disp_file_off, disp, target, mnem, size)
        self._scan_pdata(); self._scan_linear()
    def _add(self,i):
        try: e=i.encoding
        except Exception: return
        if not e.disp_size or e.disp_size!=4: return
        if 'rip' not in i.op_str: return
        m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',i.op_str)
        if not m: return
        dd=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
        off=self.p.va2o(i.address)+e.disp_offset
        if struct.unpack_from('<i',self.d,off)[0]!=dd: return
        self.map[i.address]=(off,dd,i.address+i.size+dd,i.mnemonic,i.size)
    def _scan_pdata(self):
        for s,e in self.p.funcs:
            va=self.p.base+s; o=self.p.va2o(va)
            if o is None: continue
            n=min(e-s, 0x20000)
            for i in self.md.disasm(self.d[o:o+n], va): self._add(i)
    def _scan_linear(self):
        code=self.d[self.RAW:self.RAW+self.N]
        for st in range(0,len(code),2048):
            for i in self.md.disasm(code[st:st+2100], self.TA+st):
                if i.address not in self.map: self._add(i)
    def in_range(self,lo,sz):
        return {va:v for va,v in self.map.items() if lo<=v[2]<lo+sz}
    def brute(self,lo,sz):
        """kandidaty gruboj siloj - dlja sverki"""
        out=set()
        for off in range(0,self.N-4):
            disp=struct.unpack_from('<i',self.d,self.RAW+off)[0]
            for trail in (0,1,2,4):
                tg=self.TA+off+4+trail+disp
                if lo<=tg<lo+sz: out.add((self.TA+off,tg)); break
        return out
    def check(self,name,lo,sz,verbose=True):
        known=self.in_range(lo,sz)
        kn_off={self.p.va2o(va)+0 for va in known}
        kn_disp={v[0] for v in known.values()}
        miss=[]
        for dva,tg in sorted(self.brute(lo,sz)):
            if self.p.va2o(dva) in kn_disp: continue
            miss.append((dva,tg))
        if verbose:
            print("  %-14s izvestnyh ssylok %-3d ; nesverennyh kandidatov %d" % (name,len(known),len(miss)))
            for dva,tg in miss: print("      ? smeshchenie po %012x -> %012x" % (dva,tg))
        return known,miss
