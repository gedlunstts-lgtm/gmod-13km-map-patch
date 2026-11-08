---
name: The patch will not apply
about: Use this after a Garry's Mod update, or if the patcher says it does not recognise your build
labels: port needed
---

Run the patcher and paste **all** of its output here. It prints the full
SHA-256 of every file it looked at, which is exactly what a port needs:

```
gmod483k.exe -verify
```

**Do you still have the `.stock` files?**
Look in `bin\win64` for `engine.dll.stock` and the four beside it.

- [ ] yes, all five are there
- [ ] no, or only some

If you have them, you already hold everything needed to re-port this -
see CONTRIBUTING.md. It is one command and it tells you if it fails.

**Anything else**

Which game build you are on (Steam's own update date is fine), and whether
you had an earlier release of this patch working.
