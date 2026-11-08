#!/usr/bin/env python3
"""Re-port the patch to the game build currently installed.

This is the whole maintenance job in one command, and it needs nothing but
what is already on the machine of anyone who had the patch installed before
the update:

  * <file>.stock     the previous build's original, saved by the patcher
  * <file>           the new build's original, as the update left it
  * patcher/patches/*.glp    the previous build's patch, from this repository

The previous build's *patched* file is not needed as a file: it is rebuilt by
applying the old patch to the old .stock. So the reference pair the porting
document asks for is reconstructed, not hunted for.

    python3 build/report.py --patch patches/2026-11-04.glp \
                            --gmod "C:/.../GarrysMod" \
                            --out out

Then, once it reports success for every file:

    python3 build/make_patch.py <config> patcher/patches/<new-date>.glp

and open a pull request with the new .glp. The patcher embeds every patch
under patches/ and picks the one matching the files on disk, so adding one
does not break the old builds.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'lib'))
import mkpatch
from portone import port_one


def main(argv=None):
    ap = argparse.ArgumentParser(description='re-port the patch to the installed game build')
    ap.add_argument('--patch', required=True, help='the previous build\'s .glp')
    ap.add_argument('--gmod', required=True, help='the GarrysMod folder')
    ap.add_argument('--out', default='out', help='where to write the ported files')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args(argv)

    d = open(a.patch, 'rb').read()
    patch = mkpatch_parse(d)
    os.makedirs(a.out, exist_ok=True)

    print('patch:  %s' % patch['note'])
    print('game:   %s' % a.gmod)
    print('out:    %s' % a.out)
    print()

    # Rebuild every previous-build patched file in one pass: mkpatch.apply
    # walks all targets, so the resolver has to answer for all of them.
    srcmap, missing = {}, []
    for t in patch['targets']:
        live = os.path.join(a.gmod, *t.split('/'))
        old = live + '.stock'
        if not os.path.exists(old) or not os.path.exists(live):
            missing.append((t, old if not os.path.exists(old) else live))
        srcmap[t] = old
    if missing:
        for t, what in missing:
            print('  %-22s missing: %s' % (os.path.basename(t), what))
        print()
        print('A port needs, for every patched file, both the previous original')
        print('(the .stock the patcher saved) and the new one. Without the .stock')
        print('files there is nothing to diff against - verify the game files in')
        print('Steam, reinstall the previous patch release, or ask in an issue.')
        return 1

    with contextlib.redirect_stdout(io.StringIO()):
        _note, res = mkpatch.apply(a.patch, lambda k: srcmap[k])
    rebuilt = {}
    for target, recognised, matched, buf in res:
        if not recognised or not matched:
            print('  %-22s the .stock backup is not the build this patch is for'
                  % os.path.basename(target))
            return 1
        rebuilt[target] = buf

    results = []
    for t in patch['targets']:
        name = os.path.basename(t)
        live = os.path.join(a.gmod, *t.split('/'))
        old = srcmap[t]
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.dll')
        tmp.write(rebuilt[t])
        tmp.close()
        out_path = os.path.join(a.out, name)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                data, fails = port_one(old, tmp.name, live, out_path, verbose=True)
        finally:
            os.unlink(tmp.name)
        if fails:
            print('  %-22s %d item(s) could not be ported:' % (name, len(fails)))
            for va, why in fails[:10]:
                print('      %012x  %s' % (va, why))
            results.append((name, False, '%d unported' % len(fails)))
            continue
        if not a.quiet:
            for ln in buf.getvalue().split('\n'):
                sv = ln.strip()
                if sv.startswith(('references out', 'trampolines', 'point edits',
                                  'data fields', 'pointer table')):
                    print('      %s' % sv)
        print('  %-22s ported -> %s  sha256 %s' %
              (name, out_path, hashlib.sha256(data).hexdigest()[:16]))
        results.append((name, True, out_path))

    print()
    good = [r for r in results if r[1]]
    print('%d of %d file(s) ported.' % (len(good), len(results)))
    if len(good) != len(results):
        print()
        print('Do not ship a partial port. An unported edit is worse than none:')
        print('the game will load and then misbehave somewhere unrelated.')
        print('See docs/PORTING.md - the failure messages above say which step')
        print('could not place an edit, and that document explains each one.')
        return 1

    # Hand the next command over ready to run.
    cfg = {'note': 'GMod 483k + raised limits, build YYYY-MM-DD',
           'files': [{'target': t,
                      'stock': os.path.join(a.gmod, *t.split('/')),
                      'patched': os.path.join(a.out, os.path.basename(t))}
                     for t in patch['targets']]}
    cfg_path = os.path.join(a.out, 'config.json')
    json.dump(cfg, open(cfg_path, 'w'), indent=2)
    print()
    print('Wrote %s. Set the date in its "note", then:' % cfg_path)
    print('  python3 build/make_patch.py %s patcher/patches/<new-date>.glp' % cfg_path)
    print('  python3 build/audit.py %s/*.dll' % a.out)
    return 0


def mkpatch_parse(d):
    """Just the target list and the note - mkpatch.apply does the real work."""
    import struct
    assert d[:4] == b'GLP1', 'not a GLP1 patch'
    p = 4
    nl, = struct.unpack_from('<H', d, p); p += 2
    note = d[p:p + nl].decode(); p += nl
    nf, = struct.unpack_from('<I', d, p); p += 4
    targets = []
    for _ in range(nf):
        tl, = struct.unpack_from('<H', d, p); p += 2
        targets.append(d[p:p + tl].decode()); p += tl
        p += 64
        _osz, _nsz, ne = struct.unpack_from('<QQI', d, p); p += 20
        for _ in range(ne):
            _off, ln = struct.unpack_from('<QI', d, p); p += 12 + ln
    return {'note': note, 'targets': targets}


if __name__ == '__main__':
    sys.exit(main())
