import struct, bisect
from capstone import *

class PE:
    def __init__(self, path):
        self.d = bytearray(open(path,'rb').read())
        d = self.d
        pe = struct.unpack_from('<I', d, 0x3c)[0]
        self.pe = pe
        nsec = struct.unpack_from('<H', d, pe+6)[0]
        optsz = struct.unpack_from('<H', d, pe+20)[0]
        self.base = struct.unpack_from('<Q', d, pe+24+24)[0]
        self.sec = []
        off = pe+24+optsz
        for i in range(nsec):
            name = d[off:off+8].split(b'\0')[0].decode()
            vs, va, rs, pr = struct.unpack_from('<IIII', d, off+8)
            self.sec.append(dict(name=name, va=va, vs=vs, raw=pr, rs=rs))
            off += 40
        # pdata
        self.funcs = []
        p = self.getsec('.pdata')
        if p:
            n = p['vs']//12
            for i in range(n):
                s,e,u = struct.unpack_from('<III', d, p['raw']+i*12)
                if s==0 and e==0: continue
                self.funcs.append((s,e))
            self.funcs.sort()
        self.fstarts = [f[0] for f in self.funcs]
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def getsec(self, name):
        for s in self.sec:
            if s['name']==name: return s
        return None
    def sec_of_rva(self, rva):
        for s in self.sec:
            if s['va'] <= rva < s['va']+max(s['vs'],s['rs']): return s
        return None
    def r2o(self, rva):
        s = self.sec_of_rva(rva)
        if not s: return None
        return s['raw'] + (rva - s['va'])
    def o2r(self, off):
        for s in self.sec:
            if s['raw'] <= off < s['raw']+s['rs']: return s['va'] + (off - s['raw'])
        return None
    def va2o(self, va): return self.r2o(va - self.base)
    def o2va(self, off):
        r = self.o2r(off)
        return None if r is None else r + self.base
    def read(self, va, n):
        o = self.va2o(va)
        return bytes(self.d[o:o+n])
    def func_of(self, va):
        rva = va - self.base
        i = bisect.bisect_right(self.fstarts, rva) - 1
        if i < 0: return None
        s,e = self.funcs[i]
        if s <= rva < e: return (s+self.base, e+self.base)
        return None
    def dis(self, va, n=200, count=0):
        code = self.read(va, n)
        return list(self.md.disasm(code, va, count))
    def disfunc(self, va, limit=4000):
        f = self.func_of(va)
        if not f: f = (va, va+limit)
        code = self.read(f[0], min(f[1]-f[0], limit))
        return list(self.md.disasm(code, f[0]))
    def xrefs_to(self, target, secname='.text'):
        """find rip-relative refs and direct calls/jmps to target VA"""
        s = self.getsec(secname)
        res = []
        start = s['va'] + self.base
        code = bytes(self.d[s['raw']:s['raw']+s['vs']])
        # brute force: scan for 4-byte disp that resolves; faster: iterate disasm whole section is slow.
        # Use heuristic byte scan then verify with disasm.
        import re
        for i in range(0, len(code)-4):
            disp = struct.unpack_from('<i', code, i)[0]
            # candidate end-of-instruction positions: i+4 .. i+8
            for extra in (0,1,2,3,4):
                ipend = start + i + 4 + extra
                if ipend + 0 == 0: pass
                if ipend + disp == target:
                    res.append((start+i, extra))
        return res
