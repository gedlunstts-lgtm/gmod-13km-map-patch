# How it works

Garry's Mod inherits Source's map limits. Two separate ceilings stop a large
map, and they have nothing to do with each other.

## The coordinate ceiling

Source stores and transmits world coordinates in a fixed number of bits. The
engine, the server and the client all have to agree on that number, and the
map compilers and the editor have to agree with them. Stock, the usable world
is about 32768 units on a side, with the playable area clamped to ±16384.

This project widens it to ±261120, which is roughly 13 km on a side at the
usual 1 unit ≈ 1.9 cm.

What that takes, per module:

| module | what changes |
|---|---|
| `engine.dll` | coordinate bit widths, the world bounds array, the extent check, the lightmap and surface loaders, the max-coordinate constants |
| `server.dll` | the same bit widths, plus the min/max bounds and bit counts of every networked coordinate property |
| `client.dll` | the matching bit widths, so client and server agree on the wire |
| `shaderapidx9.dll` | draws relative to the camera instead of the world origin, which is what removes the floating-point shimmer at distance |
| `studiorender.dll` | re-applies the camera offset for model eyes, which the change above otherwise leaves pointing the wrong way |

The last two depend on each other and know it. `studiorender` looks up
`shaderapidx9` at run time, checks for a magic string at a fixed offset in a
section this project added, and only then calls into it. If the magic is not
there - a mismatched pair, a partial install - it disables its own hook
instead of crashing. That handshake is why a half-installed patch shows up as
models looking the wrong way rather than as a crash.

## The geometry ceiling

Independently of coordinates, a map that *fills* 13 km runs out of room in the
BSP format long before it runs out of coordinate range:

| limit | stock | with this patch |
|---|---|---|
| vertex indices per material batch | 65536 | 4194304 |
| leaf faces | 16-bit indices | 32-bit |
| surface edges | 16-bit | 32-bit |

The leaf-face change is the interesting one, because it has to stay backward
compatible: every stock map in the game uses the 16-bit format. The lump
header carries a version field, so the loader branches on it - version 1 reads
32-bit indices, anything else reads 16-bit. Both formats load in the same
session. Without that, every stock map fails with `Mod_LoadMarksurfaces: funny
lump size`.

## How the changes are made

Three mechanisms, in increasing order of risk:

**Changed constants.** A comparison against 14 becomes a comparison against
18; a float of 16384 becomes 262144. Nothing moves, nothing is allocated.
About two thirds of the edits are of this kind.

**Retargeted references.** A `movss` that read a shared `±16384` constant from
`.rdata` is pointed at a new constant instead. The shared constant cannot be
edited in place, because other code depends on it.

**Trampolines into added sections.** Where new logic is needed, the patch adds
a PE section, writes stubs into it, and replaces an instruction in the
original code with a jump to the stub. The stub does its work, re-executes the
instructions it displaced, and jumps back.

A section that any stub *writes* to must be marked writable. This is worth
stating because getting it wrong produces a silent access violation at exactly
the moment the stub first runs, with no console output - see `docs/PORTING.md`.

## What is not done

- The map compilers (`vbsp`, `vvis`, `vrad`) and Hammer need their own
  patches. Without them you can play a large map but not build one.
- `MAX_MAP_PLANES` is the next wall: a test map already reached 95.8% of the
  65536 limit. `NODES`, `LEAFS` and `LEAFBRUSHES` sit in the same range and
  tend to run out together.
