#!/usr/bin/env python3
"""Pack loose files into a map, so the map carries what it needs.

    bsp_pack.py in.bsp out.bsp <folder>

<folder> is laid out like the game folder: materials/..., models/..., and so
on. Everything in it is added to the map's embedded archive (lump 40); files
already in the archive are kept unless the folder has one of the same name.
A map that uses materials only its author has shows up black and purple for
everyone else - this is the fix for that.
"""
import io, os, struct, sys, zipfile

PAK = 40
HEADER = 8 + 64 * 16 + 4


def lumps(d):
    return [list(struct.unpack_from('<iiI4s', d, 8 + i * 16)) for i in range(64)]


def pack(src, dst, folder):
    d = bytearray(open(src, 'rb').read())
    assert d[:4] == b'VBSP', 'not a Source map'
    L = lumps(d)
    ofs, ln = L[PAK][0], L[PAK][1]
    files = {}
    if ln:
        with zipfile.ZipFile(io.BytesIO(bytes(d[ofs:ofs + ln]))) as z:
            for n in z.namelist():
                files[n] = z.read(n)
    kept = len(files)
    added = 0
    for root, _, names in os.walk(folder):
        for n in sorted(names):
            full = os.path.join(root, n)
            rel = os.path.relpath(full, folder).replace(os.sep, '/').lower()
            files[rel] = open(full, 'rb').read()
            added += 1
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
        for n in sorted(files):
            zi = zipfile.ZipInfo(n, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zi.external_attr = 0
            zi.create_system = 0
            z.writestr(zi, files[n])
    pak = buf.getvalue()

    last = max(o + l for o, l, _, _ in L if l)
    if ln and ofs + ln == last:
        del d[ofs:]                      # the archive is the last lump: replace it
    while len(d) % 4:
        d.append(0)
    new_ofs = len(d)
    d += pak
    struct.pack_into('<ii', d, 8 + PAK * 16, new_ofs, len(pak))
    open(dst, 'wb').write(d)
    return kept, added, len(pak)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    kept, added, size = pack(*sys.argv[1:])
    print('archive: %d file(s) kept, %d added, %d bytes' % (kept, added, size))
