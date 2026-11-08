# Contributing

The job that actually needs doing, over and over, is re-porting the patch
after a Garry's Mod update. This document is how, and you do not need to have
written any of this to do one.

## You probably already have what it takes

A port needs, for each of the five patched files, the previous build's
original and the new build's original. If the patch was installed before the
update, both are sitting in your game folder right now:

- `bin\win64\engine.dll.stock` - the previous original, saved by the patcher
- `bin\win64\engine.dll` - the new original, as the update left it

The previous build's *patched* file is not needed as a file. It is rebuilt by
applying the published patch to the `.stock` copy.

So: **keep the `.stock` files.** They are what makes the next port possible.
If they are gone, verify the game files in Steam and say so in an issue - the
port then has to wait for someone who kept theirs.

## Doing the port

```
git clone <this repo>
cd <this repo>
pip install capstone

python3 build/report.py --patch patcher/patches/<newest>.glp \
                        --gmod "C:/Program Files (x86)/Steam/steamapps/common/GarrysMod" \
                        --out out
```

It prints, per file, how many stub references, trampolines, point edits and
data fields it placed, and either writes the ported file or says exactly which
edit it could not place and why.

**If anything fails, stop.** A partial port produces a game that loads and
then misbehaves somewhere unrelated, which is worse than no patch at all.
`docs/PORTING.md` explains each failure message. Open an issue with the output
rather than shipping it.

Then check the stubs and build the patch:

```
python3 build/audit.py out/*.dll
# set the date in out/config.json, then
python3 build/make_patch.py out/config.json patcher/patches/<new-date>.glp
```

`audit.py` walks every stub and confirms it returns properly.
`make_patch.py` applies the new patch back to the stock files and compares
hashes, so a patch that does not round-trip is a patch that failed.

## Testing before you open a pull request

Build the patcher, install, and load maps in this order. The order matters:
each one fails differently and the difference is the diagnosis.

1. `gm_flatgrass` - a stock map. If this fails, the leaf-face or edge handling
   is wrong, not the coordinate work.
2. any large map built for this patch
3. drive to the far edge of the map and look back at distant geometry. Shimmer
   at distance means `shaderapidx9` did not take. Model eyes pointing the
   wrong way mean `studiorender` did not - the two depend on each other, and
   `docs/HOW-IT-WORKS.md` explains the handshake between them.

## Opening the pull request

Include:

- the new `patcher/patches/<date>.glp` (keep the old ones - the patcher embeds them
  all and picks the one matching the files on disk, so adding a build does not
  break the others)
- the full output of `report.py`, `audit.py` and `make_patch.py`
- the game build you ported to, and which maps you loaded

Do not include any game file. `.gitignore` already blocks `*.dll` and friends,
and that is deliberate: a stray DLL in the history is permanent, and the whole
standing of this project is that it ships its own bytes and nothing else.

## Other things worth doing

- **PLANES.** A test map already reached 95.8% of the 65536 plane limit.
  `NODES`, `LEAFS` and `LEAFBRUSHES` sit in the same range and run out
  together. This is the next wall.
- **The map compilers and Hammer.** Without them a large map can be played but
  not built.
- **A patcher that ports itself.** Today the patch records fixed offsets and is
  pinned to one build. The porting logic in `lib/` works from masked
  signatures instead, and roughly two thirds of the edits are plain constant
  changes that could be located at install time. That would turn "works until
  the next update" into something strangers can actually rely on. It needs a
  disassembler in Go - `golang.org/x/arch/x86/x86asm`.
