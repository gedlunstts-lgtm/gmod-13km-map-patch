#!/usr/bin/env python3
"""Port hand-written stubs living in added PE sections from one game build
to another, together with the trampolines that jump into them and any
function-pointer table entries that point at them.

What it does, in order:

  1. adds the new sections to the new stock file and copies their contents
  2. walks each stub by control flow from its entry points - a linear sweep
     would desync on the string and float data that sits between them
  3. re-resolves every reference leaving the stubs: code targets by masked
     signature, data by the instructions that reference it, and anything in
     an uninitialised tail by agreement between its nearest neighbours
  4. rewrites each trampoline, blanking the whole displaced range up to the
     address its stub returns to
  5. rewrites the pointer-table entries, locating the table by its own
     contents rather than by address

    python3 build/port_stubs.py <old-unpatched> <old-patched> <new-stock> <out>
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
from portstub import port_file, apply_tramps
from portvtbl import port_table
from pe import PE

SECTIONS = ['.ctext', '.cdata', '.cave']


def main(argv):
    if len(argv) != 5:
        print(__doc__)
        return 2
    old_unp, old_pat, stock, out = argv[1:5]

    NEW, OLD, PAT, d, newva, oldva, D, fixed, fails, runs = port_file(
        old_unp, old_pat, stock, None, secnames=tuple(SECTIONS))
    print()
    print('references re-resolved: %d' % fixed)

    ok, f2, _cov = apply_tramps(OLD, PAT, NEW, d, runs, [s for s in SECTIONS if PAT.getsec(s)], D)
    print('trampolines: %d' % ok)
    fails = list(fails) + list(f2)

    # Pointer-table entries, if this file has any.
    slots, seen = [], set()
    for name, va, _o, _n in runs:
        if name != '.rdata':
            continue
        base = va - (va % 8)
        if base in seen:
            continue
        seen.add(base)
        value, = struct.unpack_from('<Q', bytes(PAT.d), PAT.va2o(base))
        slots.append((base, value + D))
    if slots:
        slots.sort()
        res, err = port_table(OLD, PAT, NEW, d, slots)
        if err:
            fails.append((0, err))
        else:
            print('pointer table: found at %012x, %d entries rewritten' % res)

    print()
    if fails:
        print('%d item(s) could not be ported:' % len(fails))
        for va, why in fails:
            print('  %012x  %s' % (va, why))
        print()
        print('Nothing was written.')
        return 1
    open(out, 'wb').write(bytes(d))
    print('%s  MD5 %s' % (out, hashlib.md5(bytes(d)).hexdigest()))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
