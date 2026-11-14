"""Nezavisimaja proverka porta: kuda smotrjat zaglushki.

Kazhdyj perehod iz dobavlennyh sekcij naruzhu (jmp, call, uslovnyj) v novoj
sborke objazan popadat v TOT ZHE kod, v kotoryj on popadal v staroj. Sverka
idjot po stokovym fajlam obeih sborok i ne polzuetsja nichem iz togo, chem
polzovalsja perenos: esli perenos zabyl ssylku ili nashjol ne to mesto, kod
po obe storony ne sojdjotsja.

Pojavilas posle porta 13 nojabrja 2026: sem uslovnyh vyhodov iz zaglushek
dvizhka ostalis so starymi adresami, igra padala pri vhode na kartu, a vse
prezhnie proverki byli zeljonymi - oni smotreli tolko na vozvraty.
"""
import stubs as _st
import portstub

TERMINATORS = ('ret', 'retf', 'jmp', 'int3', 'ud2')


def _is_branch(x):
    return x.op_str.startswith('0x') and (
        x.mnemonic == 'call' or x.mnemonic[0] == 'j' or x.mnemonic.startswith('loop'))


def _window(P, va, want=16, limit=48):
    """Dlina celyh instrukcij ot va: ne menshe want bajt, no ne dalshe
       pervogo bezuslovnogo konca (za nim mozhet idti chuzhoe vyravnivanie)."""
    n = 0
    for x in P.md.disasm(P.read(va, limit), va):
        n += x.size
        if x.mnemonic in TERMINATORS or n >= want:
            break
    return n


def verify_exits(OS, OP, NS, NP, verbose=True):
    """OS/OP - stok i patch staroj sborki, NS/NP - novoj.
       Vozvrashchaet (provereno, [(adres_v_novom, opisanie)])."""
    newsec = [s['name'] for s in OP.sec if OS.getsec(s['name']) is None]
    rng = [(OP.base + q['va'], OP.base + q['va'] + q['vs'])
           for q in (OP.getsec(n) for n in newsec)]
    inside = lambda t: any(a <= t < b for a, b in rng)
    ents = sorted(_st.entries(OP, newsec))
    bad = []
    checked = 0
    for nm in newsec:
        so = OP.getsec(nm)
        sn = NP.getsec(nm)
        if sn is None:
            bad.append((0, 'v novom fajle net sekcii %s' % nm))
            continue
        D = sn['va'] - so['va']
        lo = OP.base + so['va']
        code = portstub.reachable(OP, ents, lo, lo + so['vs'])
        for va in sorted(code):
            x = code[va]
            if not _is_branch(x):
                continue
            t = int(x.op_str, 16)
            if inside(t):
                continue
            nva = va + D
            ys = list(NP.md.disasm(NP.read(nva, x.size), nva))
            if not ys or ys[0].mnemonic != x.mnemonic or not ys[0].op_str.startswith('0x'):
                bad.append((nva, 'v novom patche zdes ne %s' % x.mnemonic))
                continue
            nt = int(ys[0].op_str, 16)
            checked += 1
            L = _window(OS, t)
            if L == 0:
                bad.append((nva, '%s -> %012x: staraja cel ne dizassembliruetsja' % (x.mnemonic, t)))
                continue
            same, why = portstub.code_equiv(OS.read(t, L), NS.read(nt, L), t, nt, OS.md)
            if not same:
                bad.append((nva, '%s -> %012x: tam drugoj kod, chem byl po %012x (%s)' % (
                    x.mnemonic, nt, t, why)))
    if verbose:
        print('  vyhodov iz zaglushek provereno: %d, ne soshlos: %d' % (checked, len(bad)))
        for a, w in bad:
            print('    %012x  %s' % (a, w))
    return checked, bad


# --- ssylki iz pravlennyh instrukcij .text ---------------------------------
def _runs(S, P, sec='.text'):
    s = S.getsec(sec); t = P.getsec(sec)
    n = min(s['rs'], t['rs'])
    a = bytes(S.d[s['raw']:s['raw'] + n]); b = bytes(P.d[t['raw']:t['raw'] + n])
    out = []; i = 0
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            out.append((S.base + s['va'] + i, j - i)); i = j
        else:
            i += 1
    return out


def _edited_refs(S, P):
    """Vse pravlennye instrukcii .text, u kotoryh est adresnaja cel:
       {adres: (mnemonika, cel)}"""
    res = {}
    for va, ln in _runs(S, P):
        f = portstub.fstart(S, va)
        if f is None or va - f > 0x20000:
            f = va - 64
        code = P.read(f, va - f + ln + 16)
        for x in P.md.disasm(code, f):
            if x.address + x.size <= va:
                continue
            if x.address >= va + ln:
                break
            e = x.encoding
            t = None
            if e.disp_size and 'rip' in x.op_str:
                dd = int.from_bytes(x.bytes[e.disp_offset:e.disp_offset + e.disp_size],
                                    'little', signed=True)
                t = x.address + x.size + dd
            elif _is_branch(x):
                t = int(x.op_str, 16)
            if t is not None:
                res[x.address] = (x.mnemonic, t)
    return res


def _key(S, P, mn, t, newsec):
    for nm in newsec:
        q = P.getsec(nm)
        if P.base + q['va'] <= t < P.base + q['va'] + q['vs']:
            return (mn, nm, t - (P.base + q['va']))
    sec = S.sec_of_rva(t - S.base)
    nm = sec['name'] if sec else '?'
    if nm == '.text':
        seq = []
        for x in S.md.disasm(S.read(t, 32), t):
            seq.append(x.mnemonic)
            if len(seq) == 4 or x.mnemonic in TERMINATORS:
                break
        return (mn, 'kod', ' '.join(seq))
    if sec and t - S.base - sec['va'] < sec['rs']:
        return (mn, nm, bytes(S.read(t, 8)).hex())
    return (mn, nm, 'bss')


def verify_text_refs(OS, OP, NS, NP, verbose=True):
    """Mnozhestvo celej pravlennyh instrukcij dolzhno sovpast mezhdu sborkami:
       ssylki v dobavlennye sekcii - po smeshcheniju vnutri sekcii, ssylki na
       dannye - po soderzhimomu, ssylki na kod - po forme koda v celi."""
    from collections import Counter
    newsec = [s['name'] for s in OP.sec if OS.getsec(s['name']) is None]
    ko = Counter(_key(OS, OP, mn, t, newsec) for mn, t in _edited_refs(OS, OP).values())
    kn = Counter(_key(NS, NP, mn, t, newsec) for mn, t in _edited_refs(NS, NP).values())
    lost = ko - kn; extra = kn - ko
    if verbose:
        print('  pravlennyh instrukcij s adresnoj celju: bylo %d, stalo %d; ne soshlos: %d'
              % (sum(ko.values()), sum(kn.values()), sum(lost.values()) + sum(extra.values())))
        for k, c in sorted(lost.items(), key=str):
            print('    propalo  x%d  %s' % (c, k))
        for k, c in sorted(extra.items(), key=str):
            print('    lishnee  x%d  %s' % (c, k))
    return sum(ko.values()), list(lost.items()), list(extra.items())
