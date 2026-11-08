#!/usr/bin/env python3
"""Build a GLP1 patch from pairs of (stock, patched) files you have locally,
then verify it by applying it back to the stock files.

The patch records only bytes that differ. A single byte matching the original
anywhere in the output aborts the build - see lib/mkpatch.py.

    python3 build/make_patch.py config.json out.glp

config.json:
{
  "note": "GMod 483k, build 2026-11-04",
  "files": [
    {"target": "bin/win64/engine.dll",
     "stock":   "/path/to/stock/engine.dll",
     "patched": "/path/to/patched/engine.dll"}
  ]
}
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
import mkpatch


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    cfg = json.load(open(argv[1]))
    out = argv[2]
    pairs = [(f['target'], f['stock'], f['patched']) for f in cfg['files']]
    files = mkpatch.build(pairs, out, cfg.get('note', ''))

    print('%-28s %10s %10s %9s %12s' % ('file', 'stock', 'patched', 'runs', 'our bytes'))
    total = 0
    for target, a, b, runs in files:
        ours = sum(len(blob) for _, blob in runs)
        total += ours
        print('%-28s %10d %10d %9d %12d' % (os.path.basename(target), len(a), len(b), len(runs), ours))
    print()
    print('our bytes in total: %d' % total)
    print('patch file: %d bytes' % os.path.getsize(out))

    # Round trip: apply the patch to the stock files and compare hashes.
    src = {f['target']: f['stock'] for f in cfg['files']}
    want = {f['target']: hashlib.sha256(open(f['patched'], 'rb').read()).hexdigest()
            for f in cfg['files']}
    note, res = mkpatch.apply(out, lambda t: src[t])
    print()
    ok = True
    for target, recognised, matched, buf in res:
        got = hashlib.sha256(buf).hexdigest()
        good = recognised and matched and got == want[target]
        ok &= bool(good)
        print('  %-28s %s' % (os.path.basename(target), 'reproduced exactly' if good else 'MISMATCH'))
    print()
    print('round trip: ' + ('every file reproduced byte for byte' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
