# Porting to a new game build

Every Garry's Mod update invalidates the patch. Addresses move, and the
patcher refuses to touch a build it does not recognise. Re-porting is the
recurring maintenance cost of this project, and this document is the
playbook, including the mistakes that cost the most time.

## What you need

For each patched module, three files:

- **old-unpatched** - the module as the previous build shipped it
- **old-patched** - the same module with the edits already in it
- **new-stock** - the new build's module, untouched

The first two must be *the same build*. This is the single most important rule
here. Diffing a patched old build against a clean new build mixes your edits
with the vendor's changes, and the result is unusable: thousands of
differences, almost all of them address relocation.

Keep a clean copy of every patched module before each update, and keep the
unpatched original beside it. Without the pair, you are reverse-engineering
your own work.

## Running the port

Point edits - changed constants, retargeted references, data fields:

```
python3 build/port_points.py old-unpatched old-patched new-stock out.dll
```

Hand-written stubs in added sections, their trampolines, and any pointer-table
entries aiming at them:

```
python3 build/port_stubs.py old-unpatched old-patched new-stock out.dll
```

Then always:

```
python3 build/audit.py out.dll
```

## How locations are found

Not by address. Each edit site is identified by a **masked code signature**: a
window of instructions around it, with every displacement and immediate zeroed
out. Opcodes and register fields have to match; addresses and constants are
free to differ. That window is then searched for in the new build.

Two rules follow, and both were learned the hard way.

**Take the signature from the unpatched file.** A patched file has a `jmp`
where the original instruction used to be. A signature taken from it describes
code that no longer exists anywhere, and the search silently finds nothing.

**Widen before you guess.** Where several functions share a prefix - the
network property registration functions are nearly identical - a 48-byte
window matches two or three places. The porter escalates to 480 bytes, and if
that still is not unique, it breaks the tie by the *strings* each candidate
function references. One of them mentions `m_flWaterZ`, the other
`m_fHeight`; that settles it. A port that picks the wrong one of two
candidates is worse than one that fails.

## Nine things that will bite

**1. Write the whole field, not the byte difference.** A constant may have
been changed by an earlier phase of the same project. One site held three
different values: 16384 in stock, 32768 after an earlier pass, 131072 in the
reference. A byte-level delta between the last two produces nonsense when
applied to the first. Replace the entire immediate or displacement field with
the target value, and verify only the bytes *outside* that field.

**2. Patches come in layers.** If the work was done in passes - first ±32768,
then ±261120 - then porting only the top layer silently drops the bottom one.
Everywhere the second pass touched the same site, you are fine, because you
write the final value. Everywhere it did not, you lose the edit. In this
project that cost one entire debugging session: the earlier pass had *disabled*
the map extent check by replacing a conditional jump with two `nop`s, and the
later pass had no reason to touch it again.

**3. Mark added sections writable if a stub writes to them.** A stub that
stores a flag in its own section faults instantly on a read-only page. There
is no console output, no crash dialog - the game vanishes mid-load. The symptom
is indistinguishable from a mis-ported stub, so check the section
characteristics first. `lib/addsec.py` takes them as an argument for this
reason.

**4. Audit every stub for a return.** Space for stubs is allocated in fixed
steps. A stub whose body happens to fill the step exactly leaves no room for
its closing jump, and the allocator hands the next address to the next stub.
Execution then falls out of one stub into another and returns to a completely
unrelated place. This does not show up in any diff. `build/audit.py` walks
every entry point the game jumps to and checks that each stub ends in a return
or a jump back into `.text`, and that it does not overlap the next one.

**5. Blank the whole displaced range.** A trampoline is five bytes; the code
it replaces is often longer, because the stub re-executes several instructions
and returns past them. Pad with `nop` all the way to the stub's return
address, not just to the end of the first instruction. The leftovers are
normally unreachable, but a conditional jump from elsewhere landing in the
middle of them will execute whatever is left.

**6. Walk stubs by control flow, not linearly.** Added sections hold code and
data interleaved - strings, float constants, dispatch tables. A linear
disassembly desyncs on the first string and never recovers, so later stubs are
simply not seen. Start from the addresses the game's own code jumps to and
follow branches.

**7. Data in an uninitialised tail shifts unevenly.** The initialised part of
`.data` may not move at all while the `.bss` tail shifts by the size of the
globals the vendor added. Resolve each data address by its *nearest referenced
neighbours on both sides*, and require them to agree. A section-wide constant
shift is wrong, and wrong in a way that only shows up at run time.

**8. Some data has no references at all.** A global that only the patch reads,
or one the vendor accesses through a pointer, cannot be located by looking for
instructions that reference it. The neighbour rule above is the fallback.

**9. Do not name a module after one in the standard library.** A file called
`fnmatch.py` in the tool directory shadows Python's own, `shutil` imports it,
and the analysis script exits silently with no output. An hour went into that.

## When you have lost the reference pair

If the patched copy of a module is gone - overwritten by an update before it
was backed up - the edits can sometimes still be recovered from a *different*
build, by pairing functions on the strings they reference. String literals do
not move between builds, so a function that references a unique string gives
an exact correspondence, with no guessing.

```
python3 -c "
import sys; sys.path.insert(0,'lib')
from strpair import pairs
from pe import PE
a=PE('old.dll'); b=PE('new.dll')
print(len(pairs(a,b)), 'function pairs')
"
```

On a 5.7 MB engine this yields around 2600 pairs - the functions that log or
report errors, which is most of the ones that enforce a limit. Compare paired
functions byte for byte and filter out branch and reference relocation.

Two cautions. Do not require the paired functions to have the same instruction
*count*: replacing one two-byte conditional jump with two one-byte `nop`s
changes it, and that is exactly the kind of edit you are looking for. And
expect jump tables inside function bodies to show up as noise, because their
entries are relative to the function's own address.

Coverage is partial by construction - a function that references no string
cannot be paired this way - so this finds lost edits, it does not prove there
are none left.
