import sys, struct
sys.path.insert(0,'/home/claude/tools')
from pe import PE
for exe in sys.argv[1:]:
    P=PE(exe); d=P.d
    pe=P.pe
    magic=struct.unpack_from('<H',d,pe+24)[0]
    ddoff = pe+24+(112 if magic==0x20b else 96)
    imp_rva, imp_sz = struct.unpack_from('<II', d, ddoff+8)
    def rva2off(r):
        for s in P.sec:
            if s['va']<=r<s['va']+max(s['vs'],s['rs']): return s['raw']+(r-s['va'])
        return None
    o=rva2off(imp_rva)
    names=[]
    while True:
        ilt,ts,fc,nameRva,iat = struct.unpack_from('<IIIII', d, o)
        if nameRva==0: break
        no=rva2off(nameRva)
        nm=bytes(d[no:d.index(b'\0',no)]).decode('ascii','replace')
        names.append(nm)
        o+=20
    import os
    print(f'=== {os.path.basename(exe)}')
    sysdlls={'kernel32.dll','user32.dll','advapi32.dll','ws2_32.dll','shell32.dll','ole32.dll',
             'oleaut32.dll','gdi32.dll','winmm.dll','psapi.dll','shlwapi.dll','dbghelp.dll',
             'api-ms-win-crt-runtime-l1-1-0.dll','version.dll','crypt32.dll','imagehlp.dll','rpcrt4.dll'}
    game=[n for n in names if n.lower() not in sysdlls and not n.lower().startswith('api-ms-') and not n.lower().startswith('vcruntime') and not n.lower().startswith('msvcp') and not n.lower().startswith('ucrtbase')]
    other=[n for n in names if n not in game]
    print('  ИЗ ПАПКИ ИГРЫ:', ', '.join(game) if game else 'нет')
    print('  системные/CRT :', len(other))
