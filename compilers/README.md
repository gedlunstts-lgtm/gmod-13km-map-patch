# The map compilers

The binaries are not in this repository. They are the release asset
`compilers.zip`; this is the note that ships inside it.

```
gmod483k map compilers
======================

vbsp_483k.exe, vvis_483k.exe and vrad_483k.exe are the Source map compilers
with the limits raised to match the gmod483k game patch:

  map coordinate range        +-16384   ->  +-262144
  vertices                     65 536   ->    400 000
  edges                       256 000   ->  1 000 000
  surfedges                   512 000   ->  2 000 000
  vertex normal indices       256 000   ->  1 000 000
  leaf-face indices            16 bit   ->  32 bit

Two of these change the map file itself: the EDGES lump is written with
version 1 and 32-bit vertex indices, and the LEAFFACES lump with version 1
and 32-bit face indices. A map built with these compilers therefore loads
only in a game that has the gmod483k patch installed.

Using them
----------
Put this archive, unpacked or not, next to gmod483k.exe and run the patcher.
It copies the three programs into GarrysMod\bin\win64, the two .bat files
into the GarrysMod folder, and points Hammer++ at the compilers if Hammer++
already has a configuration for this game.

They must sit in bin\win64: that is where they load the game's own
filesystem_stdio.dll and vphysics.dll from. They need the 64-bit branch of
the game.

  HAMMER483.bat   starts Hammer++ with VPROJECT set to this game. Use it
                  instead of starting Hammer++ directly, or the light
                  compiler may read another game's materials.
  KOMPIL483.bat   drag a .vmf onto it to run vbsp, vvis and vrad in turn.

Where they come from
--------------------
These are not Garry's Mod files. They are a build of the compilers from
Valve's Source SDK 2013 (github.com/ValveSoftware/source-sdk-2013, commit
be57e3d01ac7d7aa6a2cacbfef187c0b46616db0), distributed under the Source 1
SDK licence, which is the LICENSE file in this archive; the third-party
notices it requires are in thirdpartylegalnotices.txt.

How they were made, plainly: the SDK source was changed for the coordinate
range and built once; that build is in base\. The build tree was not kept,
so those source changes are not available as a diff. Everything after that -
the wider edges and leaf faces and the raised array limits - was done on the
built binaries by the scripts in the project's archive\ folder (mkvbsp*.py,
mkvvis*.py, mkvrad*.py). base\ is what those scripts start from.

  vbsp_483k.exe   94673fa1492b6e2e0dbd7295cbab9a26bd3620c041f46a6a3798ae603acdef2a
  vvis_483k.exe   dbe8b953739a700f5e21a3a8279d0cfade54fd41787a2749ce085ef593681f15
  vrad_483k.exe   a473756524deaada39e20d57905ca209097ce791184d3c47c9a06cd61f0d7078
  base\vbsp_src.exe  2b34d2c42bb79761b1ca032c6132de18b1f72f819b742c4e25271272b61186aa
  base\vvis_src.exe  91f0311efaae05bf7da2eedc7bcc0b37136c198b6d0f09745bb06a86907296dc
  base\vrad_src.exe  13f493d52654e2a855e6be2c9768f04d33c8ab170f6b74a85c271828d4136166

Free of charge, no warranty. Not affiliated with Valve or Facepunch Studios.

```
