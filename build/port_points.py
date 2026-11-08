#!/usr/bin/env python3
"""Port point edits (changed constants, retargeted references, data fields)
from one game build to another.

You need three files:

  old-unpatched   the file as the old build shipped it
  old-patched     the same file with the edits you want to carry over
  new-stock       the new build's file, untouched

Every edit is located in the new build by a masked code signature taken from
old-unpatched - never by a fixed address, and never from a patched file,
because a patched file no longer holds the instruction the signature describes.

    python3 build/port_points.py <old-unpatched> <old-patched> <new-stock> <out>
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
from portcoord4 import run


def main(argv):
    if len(argv) != 5:
        print(__doc__)
        return 2
    old_unp, old_pat, stock, out = argv[1:5]
    d, fails = run(old_unp, old_pat, stock, out)
    print()
    if fails:
        print('%d edit(s) could not be ported:' % len(fails))
        for va, why in fails:
            print('  %012x  %s' % (va, why))
        print()
        print('Nothing was written. An unported edit is worse than none at all.')
        return 1
    print('MD5 %s' % hashlib.md5(bytes(d)).hexdigest())
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
