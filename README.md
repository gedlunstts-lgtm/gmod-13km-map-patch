# gmod483k

Big maps for Garry's Mod.

tg channel: https://t.me/aviantproject

Normally a GMod map can't be bigger than about 800 meters across. Go past
that and things break: you can't spawn stuff, props fall through the floor,
models start shaking. This patch pushes the edge out to about 13 km, so you
can build a whole city on one map and drive around it with your friends.

It also raises a few other limits that a map this big runs into, like how
many static props it can have (16384 before, 524288 now).

## How to install

1. Go to [Releases](../../releases) and download `gmod483k.exe`.
2. Close Garry's Mod.
3. Run `gmod483k.exe`. It finds your game by itself, patches it and tells you
   when it's done.

That's it. You need the 64-bit version of the game (`x86-64` branch in
Steam's Betas tab).

If something doesn't match, for example your game version is different, the
patcher won't touch anything and will just tell you.

**Playing together:** everyone on the server needs the patch, otherwise
you won't be able to join each other.

## How to remove it

Run `gmod483k.exe -restore`, or use "Verify integrity of game files" in
Steam. Either one gives you the original game back.

## If you want to make maps

You'll need Hammer++ for Garry's Mod, **version 8873**. Get it from the
[official Hammer++ page](https://github.com/ficool2/HammerPlusPlus-Website/releases)
(the Garry's Mod archive) and install it into the game like it says there.
Version 8872 is also supported, but on the current Garry's Mod its model
browser turns every window black, so use 8873.

Then put `compilers.zip` from our Releases next to `gmod483k.exe` and run the
patcher. It will fix Hammer++ so it works on big maps, add the map compilers
that can handle them, and set Hammer++ up for your game folder: where the game
and its `gameinfo.txt` are, which compilers to run, and the `-blocksize 8192`
option the compiler needs on big maps. Nothing to set by hand. Run the patcher
again after you reinstall Hammer++ or move the game. Close Hammer++ before
you run it.

Maps made this way only work in a patched game.

## When Garry's Mod updates

An update puts the original game files back, and the patch won't install
until it's updated for the new version. Just wait for a new release here.

## Is this legal / safe?

There are no Garry's Mod files in this repository. The patcher only carries
the small changes we made and applies them to the game you already have.
Your original files are kept next to the patched ones (`.stock`), so you can
always go back. You need your own copy of the game.

We are not connected to Facepunch, Valve or the author of Hammer++.

---

## Technical part

### What exactly gets changed

| limit | stock | patched |
|---|---|---|
| map coordinate range | ±16384 | ±261120 |
| static props per map | 16384 | 524288 |
| vertex indices per material batch | 65536 | 4194304 |
| leaf faces | 16-bit | 32-bit |
| node first-face index | 16-bit | 32-bit |
| surface edges | 16-bit | 32-bit |
| network coordinate bits | 14 | 18 |

Game files, all in `bin\win64`: `engine.dll`, `client.dll`, `server.dll`,
`shaderapidx9.dll`, `studiorender.dll`. Hammer++ 8873 or 8872: `hammerplusplus_dll.dll`
and the `@mapsize` line in its FGD. Compilers (with `compilers.zip`):
`vbsp_483k.exe`, `vvis_483k.exe`, `vrad_483k.exe`, built from Valve's Source
SDK 2013 under its licence, see [compilers/README.md](compilers/README.md).

Supported game build: 2026-11-13. Patches are pinned to exact builds by
SHA-256 of the original and the result.

### Patcher options

```
gmod483k.exe              install
gmod483k.exe -verify      show what is installed, change nothing
gmod483k.exe -restore     put the original files back
gmod483k.exe -no-hammer   leave Hammer++ alone
gmod483k.exe -maps        only copy maps from a maps folder or maps.zip next to the exe
gmod483k.exe -compilers   only install the compilers
gmod483k.exe -gmod "D:\SteamLibrary\steamapps\common\GarrysMod"
```

### Docs

- [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) - the limits and how each one is lifted
- [docs/PATCH-SITES.md](docs/PATCH-SITES.md) - every patched address
- [docs/PORTING.md](docs/PORTING.md), [CONTRIBUTING.md](CONTRIBUTING.md) - porting to a new game build
- [docs/FORMAT.md](docs/FORMAT.md) - the patch file format

### Building

```
cd patcher
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ../gmod483k.exe .
```

The Python tools in `build/` and `lib/` need Python 3 and
[capstone](https://www.capstone-engine.org/).

## Licence

MIT. See [LICENSE](LICENSE).
