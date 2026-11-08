# gmod483k

Raises Garry's Mod's map limits so a map can be about **13 × 13 km** instead of
the stock 32768 units on a side, and lifts the geometry ceilings a map that
size runs into.
Rn there are no compilers because i need time to create byte to byte patch of hammer++ and compiler dll files

| limit | stock | with this patch |
|---|---|---|
| map coordinate range | ±16384 | ±261120 |
| network coordinate bits | 14 | 18 |
| vertex indices per material batch | 65536 | 4194304 |
| leaf faces | 16-bit | 32-bit, both formats readable |
| surface edges | 16-bit | 32-bit |

Five files are patched, all under `bin\win64`: `engine.dll`, `client.dll`,
`server.dll`, `shaderapidx9.dll`, `studiorender.dll`.

## This repository contains no Garry's Mod file

It contains a patch that lists only the bytes this project changes, a patcher
that applies it to the files already on your disk, and the tools that produced
it.

The patch is 56 KB. Every byte in it is this project's own work, and that is
enforced rather than claimed: the builder ends a recorded range at the first
byte that matches the original, then asserts per range that none did, so a
patch which would carry an original byte fails to build. See
[docs/FORMAT.md](docs/FORMAT.md).

Builds are pinned by SHA-256 of the original and of the result. A hash
identifies a build without reproducing any of it.

## Using it

Grab `gmod483k.exe` from [Releases](../../releases), close Garry's Mod and
Hammer, and run it.

```
gmod483k.exe              install
gmod483k.exe -verify      report what is currently installed
gmod483k.exe -restore     put the original files back
gmod483k.exe -maps        install only the maps, leave the game files alone
gmod483k.exe -gmod "D:\SteamLibrary\steamapps\common\GarrysMod"
```

Double-clicking it works: the window stays open until you press Enter.

### Maps

If a `maps` folder or a `maps.zip` containing `.bsp` files sits next to the
patcher, it copies them into the game after patching, skipping any that are
already there unchanged. Maps are kept beside the patcher rather than inside
it so that someone who only wants the patch is not made to download tens of
megabytes of them.

It finds the game through Steam's library list, keeps every original beside
the patched one as `<name>.stock`, and verifies each file both before and
after writing. If anything is not the exact supported build it stops and
writes nothing at all - not even the files that did match.

### Before you install

**This patch targets exact game builds.** The patcher carries one patch per
supported build and picks the one matching your files; if none does, it writes
nothing and prints the hashes it found. A Garry's Mod update means a port is
needed - see [CONTRIBUTING.md](CONTRIBUTING.md), which is one command and
needs nothing but the `.stock` backups the patcher already made. Steam's "verify
integrity of game files" reverts it too; there you can simply run the patcher
again.

**Everyone playing together needs it.** The patch changes how coordinates are
packed on the wire, so a patched client cannot join an unpatched server, or the
other way round.

**This lets you play large maps, not build them.** The map compilers and
Hammer need their own patches, which are not done yet.

You need your own purchased, installed copy of the game. This project is not
affiliated with Facepunch Studios or Valve.

## What is in here

| path | what it is |
|---|---|
| `patcher/` | the patcher, Go, standard library only; `patcher/patches/` holds one `.glp` per supported game build |
| `lib/` | the toolchain: PE reading and section surgery, masked-signature porting, stub and pointer-table porting, stub auditing, the patch format |
| `build/` | `report.py` re-ports the patch to a new game build in one command; `make_patch.py` builds the `.glp`; `audit.py` checks every stub returns properly |
| `docs/` | how it works, the site inventory, the porting playbook, the format spec |
| `archive/` | the one-off scripts this was actually worked out with, unmaintained |

## Documentation

- **[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md)** - which limits exist, what
  each module contributes, and the three mechanisms the patch uses
- **[docs/PORTING.md](docs/PORTING.md)** - how to re-port after a game update,
  and nine mistakes that cost real time
- **[docs/PATCH-SITES.md](docs/PATCH-SITES.md)** - every patched address and
  what is written there
- **[docs/FORMAT.md](docs/FORMAT.md)** - the GLP1 patch format
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - how to re-port after a game update,
  which is the job that recurs

## Building

The patcher:

```
cd patcher
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ../gmod483k.exe .
```

The patch, from your own copies of the stock and patched files:

```
cp build/config.example.json config.json   # point it at your files
python3 build/make_patch.py config.json patcher/patches/<date>.glp
```

Re-porting to the build you have installed, from the `.stock` backups the
patcher saved:

```
python3 build/report.py --patch patcher/patches/<newest>.glp --gmod "<game folder>" --out out
```

`make_patch.py` applies the patch back to the stock files and compares hashes,
so a build that does not round-trip is a build that failed. The tools need
Python 3 and [capstone](https://www.capstone-engine.org/) (`pip install
capstone`).

Reproducing the patch needs the stock and patched files for the build in
question. Re-porting to a new build additionally needs the previous build's
files, unpatched and patched, as the reference - see the porting document.

## Why a patch and not the files

Shipping the patched DLLs would mean shipping Facepunch's and Valve's code.
Shipping a list of only the bytes this project changed does not: there is no
original code in it, and it does nothing without a legitimate installation to
apply it to. Game modifications have been distributed as patches rather than
copies for decades, for exactly this reason.

## Licence

MIT, covering everything in this repository. See [LICENSE](LICENSE).
