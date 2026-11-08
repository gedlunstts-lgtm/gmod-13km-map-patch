# The GLP1 patch format

A GLP1 file lists, for each target file, the byte ranges that differ from the
original - and nothing else. It contains no byte of the original file, and is
useless without a legitimate copy of the game already installed.

## Guarantee

`lib/mkpatch.py` breaks a range at the first matching byte, so a single byte
equal to the original cannot end up inside a recorded range:

```python
def runs(a, b):
    # A gap of one byte already ends the range, so that not a single
    # matching - that is, original - byte can enter the patch.
```

It then asserts it, per range, before writing anything:

```python
assert all(a[off+k] != blob[k] for k in range(len(blob)))
```

A patch that would leak an original byte fails to build. That is a property of
the builder, not a promise in a document - run it and see.

Version pinning is by SHA-256 of the original and of the result. A hash is not
a copy: it identifies a build without reproducing any of it.

## Layout

Little-endian throughout.

```
"GLP1"                       4 bytes, magic
u16  noteLen
     note                    noteLen bytes, UTF-8, free text
u32  fileCount

per file:
  u16  targetLen
       target                targetLen bytes, path relative to the game root,
                             forward slashes
  [32] sha256                of the original file
  [32] sha256                of the result
  u64  originalSize
  u64  resultSize            may be smaller: adding a section drops the
                             Authenticode signature
  u32  runCount
  per run:
    u64  offset              in the resulting file
    u32  length
         data                length bytes
```

## Applying

1. Read the target. Its size and SHA-256 must equal `originalSize` and the
   recorded original hash, or stop.
2. Take `min(originalSize, resultSize)` bytes of it, then pad with zeros to
   `resultSize` if the file grows, or truncate if it shrinks.
3. Copy each run over that buffer at its offset.
4. The SHA-256 of the buffer must equal the recorded result hash, or stop.

Both the shrink case and the final check matter. An early version of the
reader handled growth but not truncation, and silently produced a wrong file
for the two modules whose patched form is smaller than stock.

## Reference implementations

- `lib/mkpatch.py` - builder and reader, Python
- `patcher/glp.go` - reader, Go, used by the shipped patcher
