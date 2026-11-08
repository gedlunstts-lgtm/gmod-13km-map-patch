# Patch site inventory

Generated from the shipped patch, for game build `2026-11-04`.

Each row gives an address in the module, at its preferred load base, and the
instruction or value **this project writes there**. What the game shipped at
that address is deliberately not reproduced, for the same reason it is not in
the patch: this project distributes its own bytes and nothing else. Disassemble
your own copy for the before picture - the addresses say exactly where to look.

Addresses move with every game build. They are here so the patch can be
audited, not so it can be applied by hand.

## bin/win64/engine.dll

180 changed run(s) in existing sections, plus added section(s) `.cave`.

### `.data` - 6 run(s)

| address | written by this project |
|---|---|
| `0001804f1708` | `00007fc8` - float -261120, int -931201024 |
| `0001804f170c` | `00007fc8` - float -261120, int -931201024 |
| `0001804f1710` | `000080c7` - float -65536, int -947912704 |
| `0001804f1718` | `00007f48` - float 261120, int 1216282624 |
| `0001804f171c` | `00007f48` - float 261120, int 1216282624 |
| `0001804f1720` | `00008047` - float 65536, int 1199570944 |

### `.text` - 174 run(s)

| address | written by this project |
|---|---|
| `000180077654` | `jmp 0x180e53023` |
| `00018007777b` | `mov ecx, dword ptr [rax + rcx*4]` |
| `0001800df9df` | `mov ecx, dword ptr [rax + rcx*4]` |
| `0001800dfeda` | `jmp 0x180e531d0` |
| `0001800dff17` | `mov ecx, dword ptr [rax + r13]` |
| `0001800dffee` | `add r13, 4` |
| `0001800e2b7b` | `lea r8, [rax + rcx*4]` |
| `0001800e2b92` | `mov eax, dword ptr [r8]` |
| `0001800e2b96` | `add r8, 4` |
| `0001800e3998` | `jmp 0x180e53036` |
| `0001800e3db0` | `jmp 0x180e53048` |
| `0001800e3db7` | `nop ` |
| `0001800ea60d` | `jmp 0x180e531f0` |
| `0001800ea624` | `lea r9, [r9 + 4]` |
| `0001800ea62f` | `mov ecx, dword ptr [rax + r9 - 4]` |
| `0001800ead20` | `jmp 0x180e5309b` |
| `0001800ef5ad` | `jmp 0x180e530b2` |
| `0001800ef64f` | `jmp 0x180e530c9` |
| `0001800ef89c` | `jmp 0x180e530e0` |
| `0001800efa4e` | `mov ecx, dword ptr [rax + rcx*4]` |
| `0001800f02dc` | `jmp 0x180e530f8` |
| `0001800f0528` | `jmp 0x180e5305f` |
| `0001800f0578` | `jmp 0x180e5310f` |
| `0001800f0775` | `jmp 0x180e53126` |
| `0001800f1757` | `mov ecx, dword ptr [rax + rdx*4]` |
| `0001800f2507` | `mov ecx, dword ptr [rax + rdx*4]` |
| `0001800f628b` | `mov ecx, dword ptr [rax + rcx*4 - 4]` |
| `0001800f62b1` | `shl edi, 2` |
| `0001800f62c4` | `lea rdi, [rdi + 4]` |
| `0001800f62cf` | `mov ecx, dword ptr [rax + rdi - 4]` |
| `0001800f8952` | `mov eax, dword ptr [rcx + rdx*4]` |
| `0001800f9680` | `mov ecx, dword ptr [rax + rsi*4]` |
| `0001800f970d` | `lea r14, [rsi*4 + 0x10]` |
| `0001800f973d` | `mov eax, dword ptr [rdx + r14 - 0xc]` |
| `0001800f975f` | `mov eax, dword ptr [rdx + r14 - 8]` |
| `0001800f98b5` | `mov eax, dword ptr [r14 + rdx - 8]` |
| `0001800f98d6` | `mov eax, dword ptr [r14 + rdx - 4]` |
| `0001800f9a29` | `mov eax, dword ptr [r14 + rdx - 4]` |
| `0001800f9a4a` | `mov eax, dword ptr [r14 + rdx]` |
| `0001800f9b9c` | `mov eax, dword ptr [r14 + rdx]` |
| `0001800f9bb4` | `mov eax, dword ptr [r14 + rdx + 4]` |
| `0001800f9c19` | `add r14, 0x10` |
| `0001800f9d28` | `jmp 0x180e53200` |
| `0001800f9d3d` | `mov eax, dword ptr [rdx + r11]` |
| `0001800f9d5e` | `mov eax, dword ptr [rdx + r11 + 4]` |
| `0001800f9d64` | `add r11, 4` |
| `000180108640` | `mov ecx, dword ptr [rax + rdx*4]` |
| `000180114470` | `jmp 0x180e53140` |
| `000180114541` | `cmp eax, 0x1e847e` |
| `000180114596` | `call 0x180e531c0` |
| `0001801145d8` | `mov ecx, dword ptr [rsi + rax*4]` |
| `000180114c15` | `call 0x180e53310` |
| `0001801164e2` | `jmp 0x180e53230` |
| `000180117740` | `jmp 0x180e53000` |
| `0001801179be` | `jmp 0x180e53580` |
| `000180117a30` | `jmp 0x180e535a0` |
| `000180117e06` | `jmp 0x180e53440` |
| `000180121e8b` | `mov ecx, dword ptr [rax + rdi*4]` |
| `000180121ec1` | `mov ecx, dword ptr [rax + rdi*4 + 4]` |
| `000180121ef9` | `mov ecx, dword ptr [rax + rdi*4 + 8]` |
| `000180121f34` | `mov ecx, dword ptr [rax + rdi*4 + 0xc]` |
| `0001801225bf` | `mov ecx, dword ptr [rax + r15*4]` |
| `0001801225f6` | `mov ecx, dword ptr [rax + r15*4 + 4]` |
| `00018012262f` | `mov ecx, dword ptr [rax + r15*4 + 8]` |
| `00018012266b` | `mov ecx, dword ptr [rax + r15*4 + 0xc]` |
| `0001801295ca` | `jmp 0x180e53210` |
| `0001801296d7` | `mov ecx, dword ptr [rax + r8]` |
| `000180129708` | `mov ecx, dword ptr [rax + r12 + 4]` |
| `00018012973e` | `mov ecx, dword ptr [rax + r12 + 8]` |
| `0001801297e1` | `add r12, 4` |
| `00018013dafa` | `jmp 0x180e53076` |
| `00018013db77` | `mov ecx, dword ptr [rax + rcx*4]` |
| `00018013dd35` | `jmp 0x180e53088` |
| `00018013e27e` | `mov ecx, dword ptr [rax + rcx*4]` |
| `00018013e537` | `mov ecx, dword ptr [rax + rcx*4]` |
| `00018013e5ac` | `mov ecx, dword ptr [rax + rcx*4 + 4]` |
| `00018013e61c` | `mov ecx, dword ptr [rax + rcx*4 + 8]` |
| `00018013e68c` | `mov ecx, dword ptr [rax + rcx*4 + 0xc]` |
| `00018013e711` | `mov ecx, dword ptr [rax + rcx*4]` |
| `00018013e81b` | `mov ecx, dword ptr [rax + rcx*4]` |
| `00018013e88f` | `mov ecx, dword ptr [rax + rcx*4 + 4]` |
| `00018013e8f4` | `mov ecx, dword ptr [rax + rcx*4 + 8]` |
| `00018013e959` | `mov ecx, dword ptr [rax + rcx*4 + 0xc]` |
| `00018013e9da` | `mov ecx, dword ptr [rax + rcx*4]` |
| `00018014f4ca` | `mov r8d, 0x10` |
| `00018014f559` | `mov r8d, 0x10` |
| `00018014f5e8` | `mov r8d, 0x10` |
| `0001801697d7` | `mov ecx, dword ptr [rax + rcx*4]` |
| `00018017f5e3` | `jmp 0x180e534e0` |
| `00018017fc40` | `cmp eax, 0x10000000` |
| `00018017ffb0` | `jmp 0x180e53260` |
| `000180180108` | `jmp 0x180e53290` |
| `000180180200` | `jmp 0x180e532c0` |
| `00018019e8e3` | `mov eax, 0x13` |
| `00018021193a` | `cmp ecx, 0x10` |
| `00018021193f` | `lea eax, [rcx - 0x10]` |
| `000180211945` | `and r9d, dword ptr [rip + 0xc41ce0]` |
| `000180211954` | `shr edx, 0x10` |
| `0001802119b2` | `jmp 0x180e53500` |
| `000180211a37` | `shl r9d, 0x10` |
| `000180211a3b` | `sar r9d, 0x10` |
| `000180211ac0` | `cmp ecx, 0x10` |
| `000180211ac5` | `lea eax, [rcx - 0x10]` |
| `000180211acb` | `and r9d, dword ptr [rip + 0xc41b5a]` |
| `000180211ada` | `shr edx, 0x10` |
| `000180211b38` | `jmp 0x180e53510` |
| `000180211bbd` | `shl r9d, 0x10` |
| `000180211bc1` | `sar r9d, 0x10` |
| `000180211c46` | `cmp ecx, 0x10` |
| `000180211c4b` | `lea eax, [rcx - 0x10]` |
| `000180211c51` | `and r9d, dword ptr [rip + 0xc419d4]` |
| `000180211c60` | `shr edx, 0x10` |
| `000180211cba` | `jmp 0x180e53520` |
| `000180211d42` | `shl r9d, 0x10` |
| `000180211d46` | `sar r9d, 0x10` |
| `0001802136a9` | `movss xmm4, dword ptr [rip + 0xc3ff5f]` |
| `0001802136bb` | `movss xmm3, dword ptr [rip + 0xc3ff55]` |
| `0001802136c3` | `movss xmm5, dword ptr [rip + 0xc3ff49]` |
| `0001802137bb` | `jmp 0x180e535e0` |
| `0001802138a9` | `movss xmm3, dword ptr [rip + 0xc3fd67]` |
| `0001802138bb` | `movss xmm4, dword ptr [rip + 0xc3fd59]` |
| `0001802138e8` | `comiss xmm1, dword ptr [rip + 0xc3fd21]` |
| `0001802138f6` | `comiss xmm1, dword ptr [rip + 0xc3fd17]` |
| `000180213961` | `comiss xmm2, dword ptr [rip + 0xc3fca8]` |
| `00018021396f` | `comiss xmm2, dword ptr [rip + 0xc3fc9e]` |
| `0001802139ae` | `jmp 0x180e53560` |
| `0001802139d9` | `comiss xmm2, dword ptr [rip + 0xc3fc40]` |
| `000180213a1b` | `comiss xmm2, dword ptr [rip + 0xc3fc02]` |
| `0001802165c8` | `mov dword ptr [rsi + rbx], 0xc8800000` |
| `0001802165d1` | `mov dword ptr [rsi + rbx + 4], 0xc8800000` |
| `0001802165dc` | `mov dword ptr [rsi + rbx + 8], 0xc8000000` |
| `00018021712c` | `movss xmm5, dword ptr [rip + 0xc3c4f4]` |
| `0001802171de` | `mov dword ptr [r9], 0x4b800000` |
| `0001802171e5` | `mov dword ptr [r8], 0x4b800000` |
| `0001802171ec` | `mov dword ptr [r10], 0x4b800000` |
| `0001802172a1` | `mov dword ptr [r9], 0x4b800000` |
| `0001802172ec` | `mov dword ptr [r8], 0x4b800000` |
| `000180217308` | `mov dword ptr [r9 + 4], 0x4b800000` |
| `000180217310` | `mov dword ptr [r8 + 4], 0x4b800000` |
| `000180217318` | `mov dword ptr [r10 + 4], 0x4b800000` |
| `0001802173d0` | `mov dword ptr [r9 + 4], 0x4b800000` |
| `00018021740f` | `mov dword ptr [r8 + 4], 0x4b800000` |
| `00018021742e` | `mov dword ptr [r9 + 8], 0x4b800000` |
| `000180217436` | `mov dword ptr [r8 + 8], 0x4b800000` |
| `00018021743e` | `mov dword ptr [r10 + 8], 0x4b800000` |
| `0001802174f4` | `mov dword ptr [r9 + 8], 0x4b800000` |
| `00018021752e` | `mov dword ptr [r8 + 8], 0x4b800000` |
| `000180217662` | `movss xmm7, dword ptr [rip + 0xc3bfbe]` |
| `00018021768e` | `mov dword ptr [r10], 0x4b800000` |
| `000180217712` | `mov dword ptr [r10], 0x4b800000` |
| `000180217759` | `mov dword ptr [r10 + 4], 0x4b800000` |
| `0001802177d4` | `mov dword ptr [r10 + 4], 0x4b800000` |
| `000180217819` | `mov dword ptr [r10 + 8], 0x4b800000` |
| `0001802300a5` | `nop ` |
| `0001802300ab` | `jmp 0x1802300c5` |
| `0001802b20e7` | `mov r8d, 0x12` |
| `0001802b228d` | `mov r8d, 0x12` |
| `0001802b2336` | `mov r8d, 0x12` |
| `0001802b32ce` | `cmp ecx, 0x12` |
| `0001802b32d3` | `lea r9d, [rcx - 0x12]` |
| `0001802b32da` | `and ebx, 0x3ffff` |
| `0001802b32e9` | `shr r8d, 0x12` |
| `0001802b3342` | `mov esi, 0x12` |
| `0001802b3691` | `cmp ecx, 0x12` |
| `0001802b369a` | `lea eax, [rcx - 0x12]` |
| `0001802b36a0` | `and r9d, 0x3ffff` |
| `0001802b36af` | `shr edx, 0x12` |
| `0001802b373b` | `mov ebx, 0x12` |
| `0001802b3918` | `cmp ecx, 0x12` |
| `0001802b391d` | `lea eax, [rcx - 0x12]` |
| `0001802b3923` | `and r9d, 0x3ffff` |
| `0001802b3932` | `shr edx, 0x12` |
| `0001802b393a` | `mov ebx, 0x12` |

### `.cave` - added section

- virtual address `00e53000`, 8192 bytes reserved
- 1223 non-zero bytes: hand-written stubs and constants, entirely this project's own code

## bin/win64/client.dll

7 changed run(s) in existing sections.

### `.data` - 1 run(s)

| address | written by this project |
|---|---|
| `000180874120` | `00008048` - float 262144, int 1216348160 |

### `.text` - 6 run(s)

| address | written by this project |
|---|---|
| `000180517b3e` | `cmp ecx, 0x12` |
| `000180517b43` | `lea r9d, [rcx - 0x12]` |
| `000180517b4a` | `and ebx, 0x3ffff` |
| `000180517b59` | `shr r8d, 0x12` |
| `000180517bb2` | `mov esi, 0x12` |
| `0001805225b7` | `mov r8d, 0x12` |

## bin/win64/server.dll

26 changed run(s) in existing sections, plus added section(s) `.cave`.

### `.data` - 1 run(s)

| address | written by this project |
|---|---|
| `000180ca1af8` | `00008048` - float 262144, int 1216348160 |

### `.text` - 25 run(s)

| address | written by this project |
|---|---|
| `000180088d60` | `movss xmm7, dword ptr [rip + 0xfd92a8]` |
| `000180088d6f` | `movss xmm6, dword ptr [rip + 0xfd929d]` |
| `000180088da2` | `mov dword ptr [rsp + 0x20], 0x15` |
| `000180089110` | `movss xmm7, dword ptr [rip + 0xfd8ef8]` |
| `00018008911f` | `movss xmm6, dword ptr [rip + 0xfd8eed]` |
| `000180089152` | `mov dword ptr [rsp + 0x20], 0x15` |
| `0001802dec9b` | `movss xmm6, dword ptr [rip + 0xd8335d]` |
| `0001802ded09` | `movss xmm6, dword ptr [rip + 0xd832f3]` |
| `0001802fdedd` | `movss xmm0, dword ptr [rip + 0xd6412b]` |
| `0001802fdee5` | `movss xmm1, dword ptr [rip + 0xd64127]` |
| `0001802fdf06` | `mov dword ptr [rsp + 0x20], 0x17` |
| `00018032f903` | `movss xmm7, dword ptr [rip + 0xd32705]` |
| `00018032f912` | `movss xmm6, dword ptr [rip + 0xd326fa]` |
| `00018032f944` | `mov dword ptr [rsp + 0x20], 0x15` |
| `00018032f97d` | `mov dword ptr [rsp + 0x20], 0x15` |
| `00018032f9b5` | `mov dword ptr [rsp + 0x20], 0x15` |
| `00018032f9ed` | `mov dword ptr [rsp + 0x20], 0x15` |
| `00018032fa25` | `mov dword ptr [rsp + 0x20], 0x15` |
| `00018032fa5d` | `mov dword ptr [rsp + 0x20], 0x15` |
| `0001807f61c7` | `mov r8d, 0x12` |
| `0001807feb3e` | `cmp ecx, 0x12` |
| `0001807feb43` | `lea r9d, [rcx - 0x12]` |
| `0001807feb4a` | `and ebx, 0x3ffff` |
| `0001807feb59` | `shr r8d, 0x12` |
| `0001807febb2` | `mov esi, 0x12` |

### `.cave` - added section

- virtual address `01062000`, 4096 bytes reserved
- 8 non-zero bytes: hand-written stubs and constants, entirely this project's own code

## bin/win64/shaderapidx9.dll

10 changed run(s) in existing sections, plus added section(s) `.ctext`, `.cdata`.

### `.rdata` - 8 run(s)

| address | written by this project |
|---|---|
| `00018007b5a8` | `b0550f80` - float -1.40827e-39, int -2146478672 |
| `00018007b5b0` | `00560f80` - float -1.40838e-39, int -2146478592 |
| `00018007b5c0` | `30580f80` - float -1.40917e-39, int -2146478032 |
| `00018007b618` | `10590f80` - float -1.40948e-39, int -2146477808 |
| `00018007b620` | `10580f80` - float -1.40912e-39, int -2146478064 |
| `00018007b638` | `f0570f80` - float -1.40908e-39, int -2146478096 |
| `00018007b650` | `90590f80` - float -1.40966e-39, int -2146477680 |
| `00018007b720` | `c0590f80` - float -1.40973e-39, int -2146477632 |

### `.text` - 2 run(s)

| address | written by this project |
|---|---|
| `0001800159b1` | `jmp 0x1800f5a60` |
| `000180015c2a` | `jmp 0x1800f5a30` |

### `.ctext` - added section

- virtual address `000f5000`, 4096 bytes reserved
- 2319 non-zero bytes: hand-written stubs and constants, entirely this project's own code

### `.cdata` - added section

- virtual address `000f6000`, 24576 bytes reserved
- 23 non-zero bytes: hand-written stubs and constants, entirely this project's own code

## bin/win64/studiorender.dll

5 changed run(s) in existing sections, plus added section(s) `.ctext`, `.cdata`.

### `.text` - 5 run(s)

| address | written by this project |
|---|---|
| `0001800102e9` | `jmp 0x1808351c0` |
| `000180010353` | `jmp 0x1808351f0` |
| `00018001038d` | `jmp 0x180835230` |
| `0001800103c7` | `jmp 0x180835270` |
| `0001800103fd` | `jmp 0x1808352a0` |

### `.ctext` - added section

- virtual address `00835000`, 4096 bytes reserved
- 522 non-zero bytes: hand-written stubs and constants, entirely this project's own code

### `.cdata` - added section

- virtual address `00836000`, 4096 bytes reserved
- 4 non-zero bytes: hand-written stubs and constants, entirely this project's own code

