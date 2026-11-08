---
name: Something is broken in game
about: Crashes, visual faults, maps that will not load
labels: bug
---

**What happens**

**Which maps**
Please say whether a stock map such as `gm_flatgrass` also fails - that single
fact splits the cause in half.

**Does it look like one of these**
- geometry shimmering at distance - `shaderapidx9` is not taking effect
- model eyes pointing the wrong way - `studiorender` is not

**Patcher output**

```
gmod483k.exe -verify
```

**Console log**
`garrysmod/console.log`, if there is one. Note that a hard crash leaves the
log buffer unflushed, so the last lines may be missing - that is normal and
not a sign of where it died.
