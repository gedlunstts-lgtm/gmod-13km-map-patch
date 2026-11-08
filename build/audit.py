#!/usr/bin/env python3
"""Audit every stub in a patched binary's added sections.

For each address the game's own code jumps or calls into, it walks the stub
and checks that it ends in a return or a jump back into .text, and that it
does not run past its own end into the next stub.

This catches the single worst failure mode of this kind of patching: a stub
whose return jump did not fit in the space allocated for it, which then falls
through into unrelated code. That bug is invisible in a diff and crashes the
game somewhere unrelated.

    python3 build/audit.py <file.dll> [more.dll ...]
"""
import os
import subprocess
import sys

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib')

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(2)
sys.exit(subprocess.call([sys.executable, os.path.join(LIB, 'audit_cave.py')] + sys.argv[1:]))
