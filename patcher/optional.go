package main

// Optional components.
//
// The game patch is all-or-nothing: five files, one build. Things that live
// next to the game but are not part of it - Hammer++ so far - are handled
// separately and never block the game patch. A component is patched when it
// is found on disk and is a build this patcher knows; otherwise it is
// reported and left alone.

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed optional/*.glp
var optionalFS embed.FS

// The map size Hammer++ is told about. The engine patch allows +-261120.
const wantMapsize = "@mapsize(-261120, 261120)"

var (
	reMapsize = regexp.MustCompile(`(?m)^[ \t]*@mapsize[ \t]*\([^)\r\n]*\)`)
	reVersion = regexp.MustCompile(`(?m)^[ \t]*@version[ \t]*\([^)\r\n]*\)[ \t]*\r?\n`)
)

const hammerFGD = "hammerplusplus_fgd.fgd"

func loadOptional() ([]release, error) {
	ents, err := fs.ReadDir(optionalFS, "optional")
	if err != nil {
		return nil, err
	}
	var out []release
	for _, e := range ents {
		b, err := optionalFS.ReadFile("optional/" + e.Name())
		if err != nil {
			return nil, err
		}
		p, err := ParsePatch(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, release{name: e.Name(), patch: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name > out[j].name })
	return out, nil
}

// findByName returns every file under root/bin with the given name. Hammer++
// has been unpacked into more than one layout over the years, so the path
// recorded in the patch is a hint, not a requirement.
func findByName(root, name string) []string {
	var out []string
	base := filepath.Join(root, "bin")
	filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if rel, _ := filepath.Rel(base, p); strings.Count(rel, string(filepath.Separator)) > 4 {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(d.Name(), name) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// optItem is one file of an optional component, matched against every
// build of that component the patcher carries.
type optItem struct {
	item
	known bool // some embedded patch recognises this file
}

func classifyOptional(root string, rels []release) []optItem {
	seen := map[string]bool{}
	var out []optItem
	for i := range rels {
		for j := range rels[i].patch.Targets {
			name := filepath.Base(filepath.FromSlash(rels[i].patch.Targets[j].Path))
			for _, live := range findByName(root, name) {
				if seen[live] {
					continue
				}
				seen[live] = true
				b, err := os.ReadFile(live)
				if err != nil {
					continue
				}
				oi := optItem{item: item{live: live, bak: live + ".stock", bytes: b, hash: hashOf(b), st: stUnknown}}
				// newest patch first; the first one that knows the file wins
				for k := range rels {
					for m := range rels[k].patch.Targets {
						t := &rels[k].patch.Targets[m]
						if !strings.EqualFold(filepath.Base(filepath.FromSlash(t.Path)), name) {
							continue
						}
						if oi.hash == t.OldHash {
							oi.t, oi.st, oi.known = t, stStock, true
						} else if oi.hash == t.NewHash {
							oi.t, oi.st, oi.known = t, stPatched, true
						}
						if oi.known {
							break
						}
					}
					if oi.known {
						break
					}
				}
				out = append(out, oi)
			}
		}
	}
	return out
}

// relTo is how a file is named in the output: its bare name, which is what
// keeps the columns readable, with the folder printed once above the list.
func relTo(root, p string) string {
	return filepath.Base(p)
}

func folderOf(root, p string) string {
	if r, err := filepath.Rel(root, filepath.Dir(p)); err == nil {
		return filepath.ToSlash(r)
	}
	return filepath.Dir(p)
}

// setMapsize makes the Hammer++ FGD declare the big map size. It is only
// called once the DLL is patched: with a stock DLL the same line makes the
// editor stop drawing its grid.
func setMapsize(root string) {
	for _, p := range findByName(root, hammerFGD) {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(b)
		var out string
		switch {
		case reMapsize.MatchString(text):
			if strings.TrimSpace(reMapsize.FindString(text)) == wantMapsize {
				fmt.Printf("  %-28s map size already set\n", relTo(root, p))
				continue
			}
			out = reMapsize.ReplaceAllString(text, wantMapsize)
		case reVersion.MatchString(text):
			nl := "\n"
			if strings.Contains(text, "\r\n") {
				nl = "\r\n"
			}
			loc := reVersion.FindStringIndex(text)
			out = text[:loc[1]] + nl + wantMapsize + nl + text[loc[1]:]
		default:
			fmt.Printf("  %-28s no @version line, left alone\n", relTo(root, p))
			continue
		}
		if _, err := os.Stat(p + ".stock"); os.IsNotExist(err) {
			if err := writeFile(p+".stock", b); err != nil {
				fmt.Printf("  %-28s could not save the backup: %v\n", relTo(root, p), err)
				continue
			}
		}
		if err := writeFile(p, []byte(out)); err != nil {
			fmt.Printf("  %-28s could not write: %v\n", relTo(root, p), err)
			continue
		}
		fmt.Printf("  %-28s map size set to +-261120\n", relTo(root, p))
	}
}

func restoreMapsize(root string) {
	for _, p := range findByName(root, hammerFGD) {
		b, err := os.ReadFile(p + ".stock")
		if err != nil {
			continue
		}
		if err := writeFile(p, b); err != nil {
			fmt.Printf("  %-28s could not write: %v\n", relTo(root, p), err)
			continue
		}
		fmt.Printf("  %-28s restored\n", relTo(root, p))
	}
}

// optional runs one of "install", "restore" or "verify" over every optional
// component. It never fails the run: the worst outcome is a file left alone.
func optional(root, mode string) {
	rels, err := loadOptional()
	if err != nil || len(rels) == 0 {
		return
	}
	items := classifyOptional(root, rels)
	fmt.Println()
	if len(items) == 0 {
		fmt.Println("Hammer++: not found under bin, nothing to do.")
		return
	}
	fmt.Println("Hammer++ (optional, needed only to build maps):")
	patched := false
	lastDir := ""
	for i := range items {
		it := &items[i]
		name := relTo(root, it.live)
		if d := folderOf(root, it.live); d != lastDir {
			fmt.Printf("  in %s\n", d)
			lastDir = d
		}
		if !it.known {
			fmt.Printf("  %-28s a build this patcher has no patch for, left alone\n", name)
			fmt.Printf("  %-28s sha256 %x\n", "", it.hash)
			continue
		}
		switch mode {
		case "verify":
			fmt.Printf("  %-28s %s\n", name, it.st)
			if it.st == stPatched {
				patched = true
			}
		case "restore":
			if it.st == stStock {
				fmt.Printf("  %-28s already original\n", name)
				continue
			}
			b, err := os.ReadFile(it.bak)
			if err != nil || hashOf(b) != it.t.OldHash {
				fmt.Printf("  %-28s no usable backup, left alone\n", name)
				continue
			}
			if err := writeFile(it.live, b); err != nil {
				fmt.Printf("  %-28s could not write: %v\n", name, err)
				continue
			}
			fmt.Printf("  %-28s restored\n", name)
		default:
			if it.st == stPatched {
				fmt.Printf("  %-28s already patched\n", name)
				patched = true
				continue
			}
			out, err := it.t.Apply(it.bytes)
			if err != nil {
				fmt.Printf("  %-28s %v\n", name, err)
				continue
			}
			if b, err := os.ReadFile(it.bak); err != nil || hashOf(b) != it.t.OldHash {
				if err := writeFile(it.bak, it.bytes); err != nil {
					fmt.Printf("  %-28s could not save the backup: %v\n", name, err)
					continue
				}
			}
			if err := writeFile(it.live, out); err != nil {
				fmt.Printf("  %-28s could not write (is Hammer++ running?): %v\n", name, err)
				continue
			}
			fmt.Printf("  %-28s patched, original kept as %s\n", name, filepath.Base(it.bak))
			patched = true
		}
	}
	switch mode {
	case "restore":
		restoreMapsize(root)
	case "verify":
	default:
		if patched {
			setMapsize(root)
		}
	}
}
