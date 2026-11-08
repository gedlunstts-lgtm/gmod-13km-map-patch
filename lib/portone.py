"""Port one patched file to a new game build, end to end.

Reference material is a pair from the previous build - the file as the game
shipped it, and the same file with the patch already in it. The target is the
new build's untouched file.

Order matters:

  1. added sections, their stubs, and every reference leaving them
  2. the trampolines that jump into those stubs
  3. function-pointer table entries aiming at the stubs
  4. point edits: changed constants and retargeted references, skipping the
     trampoline sites handled in step 2
  5. fields in data sections

Steps 1-3 must come first, because the later steps are applied on top of the
buffer they produce, not on top of the stock file.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

import struct
import hashlib
import contextlib
import io

from pe import PE
from pediff import diff
from sigport import mask_sig, find
from portcoord3 import ins_at, port_data
from portcoord4 import _narrow
from portstub import port_file, apply_tramps, fstart, neighbour_shift, locate_data
from portvtbl import port_table
import stubs as _stubs

SECTIONS = ('.ctext', '.cdata', '.cave')
WINS = ((40, 3), (72, 6), (120, 10), (200, 16), (320, 24), (480, 36))


def _quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)


def _locate(OLD, STK, va):
    """Find a code site in the new build. Signature taken from the unpatched
       reference - a patched file no longer holds the instruction."""
    for nb, pre in WINS:
        r = mask_sig(OLD, va, nb, pre)
        if not r:
            continue
        pat, msk, off, _start = r
        hits = find(STK, pat, msk)
        if len(hits) > 1:
            hits = _narrow(OLD, STK, va, hits, off)
        if len(hits) == 1:
            return hits[0] + off, None
        why = 'matched %d times (window %d/%d)' % (len(hits), nb, pre)
    return None, why


def _rip(ins):
    e = ins.encoding
    if not e.disp_size or 'rip' not in ins.op_str:
        return None
    d = int.from_bytes(ins.bytes[e.disp_offset:e.disp_offset + e.disp_size], 'little', signed=True)
    return ins.address + ins.size + d


def port_one(old_unp, old_pat, stock, out=None, verbose=True):
    OLD, PAT = PE(old_unp), PE(old_pat)
    _, _, runs, newsec = _quiet(diff, old_unp, old_pat, show=False)
    newsec = [s for s in SECTIONS if s in newsec]
    fails = []

    # --- 1-3: sections, stubs, trampolines, tables -------------------------
    if newsec:
        NEW, OLD, PAT, d, newva, oldva, D, fixed, f1, runs = port_file(
            old_unp, old_pat, stock, None, secnames=tuple(newsec), verbose=verbose)
        fails += list(f1)
        if verbose:
            print('  references out of the stubs: %d' % fixed)
        ok, f2, covered = apply_tramps(OLD, PAT, NEW, d, runs, newsec, D, verbose=verbose)
        fails += list(f2)
        if verbose:
            print('  trampolines: %d' % ok)
        slots, seen = [], set()
        for nm, va, _o, _n in runs:
            if nm != '.rdata':
                continue
            base = va - (va % 8)
            if base in seen:
                continue
            seen.add(base)
            val, = struct.unpack_from('<Q', bytes(PAT.d), PAT.va2o(base))
            slots.append((base, val + D))
        if slots:
            res, err = port_table(OLD, PAT, NEW, d, sorted(slots), verbose=verbose)
            if err:
                fails.append((0, err))
            elif verbose:
                print('  pointer table: found at %012x, %d entries' % res)
        # Chto uzhe napisano shagom 2: ne tolko adresa sajtov, no i vsjo,
        # chto popalo v vytesnennye diapazony.
        tramp_sites = {site for site, _L in covered}
        covered_ranges = list(covered)
    else:
        NEW = PE(stock)
        d = bytearray(NEW.d)
        D = 0
        tramp_sites = set()
        covered_ranges = []

    # --- 4: point edits ----------------------------------------------------
    byins, datruns = {}, []
    for nm, va, _o, _n in runs:
        if nm == '.rdata' and newsec:
            continue                      # handled as table entries
        if nm != '.text':
            datruns.append((nm, va))
            continue
        # A run can span several instructions - take all of them, not just
        # the one its first byte falls in.
        end = va + len(_o)
        ia = ins_at(OLD, va)
        if ia is None:
            continue
        cur = ia.address
        while cur < end:
            x = ins_at(OLD, cur)
            if x is None:
                break
            byins.setdefault(x.address, x)
            cur = x.address + x.size
    done = 0
    for va in sorted(byins):
        ia = ins_at(OLD, va)
        ib = ins_at(PAT, va)
        if ib is None:
            continue
        # Step 2 already wrote the trampolines and blanked the ranges they
        # displaced. Skip exactly those, and nothing else: a jmp or a nop in
        # the reference is not by itself a trampoline - the extent check is
        # disabled by turning a conditional jump into two nops, and that is
        # a real edit this step has to carry.
        if ia.address in tramp_sites:
            continue
        if any(st_ <= ia.address < st_ + L_ for st_, L_ in covered_ranges):
            continue
        if ib.mnemonic in ('jmp', 'call') and ib.op_str.startswith('0x'):
            _t = int(ib.op_str, 16)
            if any((PAT.base + [x for x in PAT.sec if x['name'] == _s][0]['va'])
                   <= _t <
                   (PAT.base + [x for x in PAT.sec if x['name'] == _s][0]['va']
                    + [x for x in PAT.sec if x['name'] == _s][0]['vs'])
                   for _s in newsec):
                continue

        # Compare the BYTE RANGE of the original instruction, not the decoded
        # instructions: an edit may change the instruction length while the
        # range stays the same - movzx of a word becoming mov of a dword plus
        # a nop is exactly that, and comparing decoded bytes misses it.
        ext = ia.size
        oldr = OLD.read(ia.address, ext)
        patr = PAT.read(ia.address, ext)
        if oldr == patr:
            continue
        nva, why = _locate(OLD, NEW, va)
        if nva is None:
            fails.append((va, why))
            continue
        o = NEW.va2o(nva)
        cur = bytes(d[o:o + ext])
        delta = [k for k in range(ext) if oldr[k] != patr[k]]
        e = ia.encoding

        # a reference retargeted into an added section: recompute it
        rb = _rip(ib) if ib.size == ext else None
        tgt_new = None
        if rb is not None and newsec:
            for _s in newsec:
                sec = [x for x in PAT.sec if x['name'] == _s][0]
                lo = PAT.base + sec['vs'] * 0 + sec['va']
                if lo <= rb < lo + sec['vs']:
                    tgt_new = newva[_s] + (rb - lo)
                    break
        if tgt_new is not None:
            fo, fs = e.disp_offset, e.disp_size
            bad = [k for k in range(ext) if not (fo <= k < fo + fs) and cur[k] != oldr[k]]
            if bad:
                fails.append((va, 'context differs at %s' % bad))
                continue
            d[o + fo:o + fo + fs] = struct.pack('<i', tgt_new - (nva + ext))
            done += 1
            continue

        if ib.mnemonic == ia.mnemonic and ib.size == ext:
            # same instruction, different number: replace the whole field,
            # because the constant may already differ between this build and
            # the reference
            field = None
            for fo, fs in ((e.imm_offset, e.imm_size), (e.disp_offset, e.disp_size)):
                if fs and all(fo <= k < fo + fs for k in delta):
                    field = (fo, fs)
                    break
            if field:
                fo, fs = field
                bad = [k for k in range(ext) if not (fo <= k < fo + fs) and cur[k] != oldr[k]]
                if bad:
                    fails.append((va, 'context differs at %s' % bad))
                    continue
                d[o + fo:o + fo + fs] = patr[fo:fo + fs]
                done += 1
                continue

        # different instruction form: take the range verbatim, but only if the
        # new build really does hold the same original code there
        if cur != oldr:
            fails.append((va, 'the new build differs in this range, not porting blind'))
            continue
        d[o:o + ext] = patr
        done += 1
    if verbose:
        print('  point edits: %d' % done)

    # --- 5: data fields ----------------------------------------------------
    seen, dd = set(), 0
    for nm, va in datruns:
        base = va - (va % 4)
        if base in seen:
            continue
        seen.add(base)
        r, err = _quiet(port_data, NEW, OLD, PAT, d, nm, base)
        if err:
            sh = neighbour_shift(OLD, NEW, base)
            if sh is None:
                fails.append((base, 'data: ' + err))
                continue
            nva = base + sh
            o = NEW.va2o(nva)
            d[o:o + 4] = PAT.read(base, 4)
        dd += 1
    if verbose and datruns:
        print('  data fields: %d' % dd)

    if fails:
        return None, fails
    if out:
        open(out, 'wb').write(bytes(d))
    return bytes(d), []
