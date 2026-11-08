// gmod483k - applies the big-map patch to Garry's Mod.
//
// The patch carries only the bytes this project changes. No byte of the
// original game files is distributed with it: the patcher reads the files
// already on your disk, confirms they are a build it has a patch for, and
// writes the differences in.
//
// Several builds can be supported at once. Every .glp under patches/ is
// embedded, and the one whose recorded original hashes match the files on
// disk is the one that gets applied.
package main

import (
	"crypto/sha256"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

//go:embed patches/*.glp
var patchFS embed.FS

const version = "1.1"

type state int

const (
	stStock state = iota
	stPatched
	stUnknown
	stMissing
)

func (s state) String() string {
	switch s {
	case stStock:
		return "stock"
	case stPatched:
		return "patched"
	case stMissing:
		return "MISSING"
	}
	return "not a known build"
}

type item struct {
	t     *Target
	live  string
	bak   string
	st    state
	hash  [32]byte
	bytes []byte
}

type release struct {
	name  string
	patch *Patch
}

func hashOf(b []byte) [32]byte { return sha256.Sum256(b) }

func loadReleases() ([]release, error) {
	ents, err := fs.ReadDir(patchFS, "patches")
	if err != nil {
		return nil, err
	}
	var out []release
	for _, e := range ents {
		b, err := patchFS.ReadFile("patches/" + e.Name())
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
	if len(out) == 0 {
		return nil, fmt.Errorf("no patches are embedded in this build of the patcher")
	}
	return out, nil
}

func classify(root string, p *Patch) []item {
	var items []item
	for i := range p.Targets {
		t := &p.Targets[i]
		live := filepath.Join(root, filepath.FromSlash(t.Path))
		it := item{t: t, live: live, bak: live + ".stock"}
		b, err := os.ReadFile(live)
		if err != nil {
			it.st = stMissing
			items = append(items, it)
			continue
		}
		it.bytes = b
		it.hash = hashOf(b)
		switch it.hash {
		case t.OldHash:
			it.st = stStock
		case t.NewHash:
			it.st = stPatched
		default:
			it.st = stUnknown
		}
		items = append(items, it)
	}
	return items
}

// pick returns the release that fits what is on disk: all stock, or all
// already patched. Anything else is reported, not guessed at.
func pick(root string, rels []release) (*release, []item, bool) {
	for i := range rels {
		items := classify(root, rels[i].patch)
		ok := true
		for _, it := range items {
			if it.st != stStock && it.st != stPatched {
				ok = false
				break
			}
		}
		if ok {
			return &rels[i], items, true
		}
	}
	return nil, classify(root, rels[0].patch), false
}

func report(items []item) {
	fmt.Println()
	for _, it := range items {
		h := ""
		if it.st != stMissing {
			h = fmt.Sprintf("sha256 %x", it.hash[:8])
		}
		fmt.Printf("  %-22s %-18s %s\n", filepath.Base(it.live), it.st, h)
	}
	fmt.Println()
}

func explainUnsupported(root string, rels []release, items []item) {
	fmt.Println("None of the embedded patches match the files on this machine.")
	fmt.Println()
	fmt.Println("Patches available in this build of the patcher:")
	for _, r := range rels {
		fmt.Printf("  %-20s %s\n", r.name, r.patch.Note)
	}
	fmt.Println()
	fmt.Println("That almost always means Garry's Mod has updated. The patch has to be")
	fmt.Println("re-ported to the new build; nothing here was changed.")
	fmt.Println()
	fmt.Println("If you had this patch installed before the update, the .stock backups")
	fmt.Println("still next to those files are exactly what a port needs. Keep them, and")
	fmt.Println("see CONTRIBUTING.md in the repository - a port is a scripted procedure,")
	fmt.Println("not guesswork, and you do not need to have written any of this to do one.")
	fmt.Println()
	fmt.Println("Full hashes of what you have, to quote in an issue:")
	for _, it := range items {
		if it.st == stMissing {
			continue
		}
		fmt.Printf("  %-22s %x\n", filepath.Base(it.live), it.hash)
	}
}

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gmod483k-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err = tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err = os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("%w\n     (if the game or Hammer is open, close it and try again)", err)
	}
	return nil
}

func install(items []item) int {
	for _, it := range items {
		b, err := os.ReadFile(it.bak)
		if err == nil && hashOf(b) != it.t.OldHash {
			fmt.Printf("%s: the existing backup is not the original. Stopping, nothing changed.\n",
				filepath.Base(it.bak))
			fmt.Println("Verify the game files through Steam, then run this again.")
			return 1
		}
	}
	done := 0
	for i := range items {
		it := &items[i]
		name := filepath.Base(it.live)
		if it.st == stPatched {
			fmt.Printf("  %-22s already patched, skipped\n", name)
			continue
		}
		if _, err := os.Stat(it.bak); os.IsNotExist(err) {
			if err := writeFile(it.bak, it.bytes); err != nil {
				fmt.Printf("  %-22s could not save the backup: %v\n", name, err)
				return 1
			}
		}
		out, err := it.t.Apply(it.bytes)
		if err != nil {
			fmt.Printf("  %-22s %v\n", name, err)
			return 1
		}
		if err := writeFile(it.live, out); err != nil {
			fmt.Printf("  %-22s could not write: %v\n", name, err)
			return 1
		}
		back, err := os.ReadFile(it.live)
		if err != nil || hashOf(back) != it.t.NewHash {
			fmt.Printf("  %-22s written, but reading it back does not match. Run -restore.\n", name)
			return 1
		}
		fmt.Printf("  %-22s patched, original kept as %s\n", name, filepath.Base(it.bak))
		done++
	}
	fmt.Println()
	fmt.Printf("Done: %d file(s) patched.\n", done)
	fmt.Println()
	fmt.Println("Worth knowing:")
	fmt.Println("  - Keep the .stock files. They are the original game files, and they are")
	fmt.Println("    what a port to the next game build is made from.")
	fmt.Println("  - Verifying the game files through Steam undoes this; just run it again.")
	fmt.Println("  - A Garry's Mod update undoes it too, and the patch will then refuse to")
	fmt.Println("    apply until someone re-ports it. See CONTRIBUTING.md.")
	fmt.Println("  - To play together, every player needs this patch: it changes how")
	fmt.Println("    coordinates are packed on the wire, so patched and unpatched do not mix.")
	fmt.Println("  - Undo at any time with:  gmod483k -restore")
	return 0
}

func restore(items []item) int {
	done, left := 0, 0
	for i := range items {
		it := &items[i]
		name := filepath.Base(it.live)
		b, err := os.ReadFile(it.bak)
		if err != nil {
			if it.st == stStock {
				fmt.Printf("  %-22s already original\n", name)
			} else {
				fmt.Printf("  %-22s no backup found, left alone\n", name)
				left++
			}
			continue
		}
		if hashOf(b) != it.t.OldHash {
			fmt.Printf("  %-22s backup is not the original, left alone\n", name)
			left++
			continue
		}
		if it.st == stStock {
			fmt.Printf("  %-22s already original\n", name)
			continue
		}
		if err := writeFile(it.live, b); err != nil {
			fmt.Printf("  %-22s could not write: %v\n", name, err)
			return 1
		}
		fmt.Printf("  %-22s restored\n", name)
		done++
	}
	fmt.Println()
	fmt.Printf("Restored %d file(s).", done)
	if left > 0 {
		fmt.Printf(" %d left alone - verify the game files through Steam to be sure.", left)
	}
	fmt.Println()
	return 0
}

func main() {
	var (
		gmod    = flag.String("gmod", "", "path to the GarrysMod folder (found automatically if omitted)")
		doRest  = flag.Bool("restore", false, "put the original files back")
		doVer   = flag.Bool("verify", false, "only report what is currently installed")
		doList  = flag.Bool("list", false, "list the game builds this patcher has a patch for")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("gmod483k %s\n", version)
		return
	}
	fmt.Printf("gmod483k %s - big map patch for Garry's Mod\n", version)

	rels, err := loadReleases()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if *doList {
		fmt.Println()
		for _, r := range rels {
			fmt.Printf("  %-20s %s\n", r.name, r.patch.Note)
			for i := range r.patch.Targets {
				t := &r.patch.Targets[i]
				fmt.Printf("      %-28s %x\n", t.Path, t.OldHash[:8])
			}
		}
		return
	}

	root := *gmod
	if root == "" {
		root = FindGMod()
	}
	if root == "" {
		fmt.Println()
		fmt.Println("Could not find Garry's Mod. Pass the folder explicitly, for example:")
		fmt.Println(`  gmod483k -gmod "D:\SteamLibrary\steamapps\common\GarrysMod"`)
		os.Exit(1)
	}
	if _, err := os.Stat(filepath.Join(root, "garrysmod", "gameinfo.txt")); err != nil {
		fmt.Printf("\n%s does not look like a GarrysMod folder.\n", root)
		os.Exit(1)
	}
	fmt.Println("game: ", root)

	rel, items, ok := pick(root, rels)
	if !ok {
		report(items)
		explainUnsupported(root, rels, items)
		os.Exit(1)
	}
	fmt.Println("patch:", rel.patch.Note)
	report(items)

	switch {
	case *doVer:
		patched, stock := 0, 0
		for _, it := range items {
			switch it.st {
			case stPatched:
				patched++
			case stStock:
				stock++
			}
		}
		switch {
		case patched == len(items):
			fmt.Println("The patch is fully installed.")
		case stock == len(items):
			fmt.Println("Everything is original. Run the patcher with no arguments to install.")
		default:
			fmt.Println("Mixed state. Run -restore, then install again.")
		}
	case *doRest:
		os.Exit(restore(items))
	default:
		os.Exit(install(items))
	}
}
