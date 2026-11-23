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

const version = "1.5.1"

type state int

const (
	stStock state = iota
	stPatched
	stOlder // not the current patch, but its saved original is this build's
	stUnknown
	stMissing
)

func (s state) String() string {
	switch s {
	case stStock:
		return "stock"
	case stPatched:
		return "patched"
	case stOlder:
		return "earlier patch"
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
			// A file left by an earlier version of this patch is not stock
			// and not the current result, but if the original saved beside
			// it is this build's, the current patch can be built from that.
			if b, err := os.ReadFile(it.bak); err == nil && hashOf(b) == t.OldHash {
				it.st = stOlder
				it.bytes = b
			}
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
			if it.st != stStock && it.st != stPatched && it.st != stOlder {
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
		if err != nil || hashOf(b) == it.t.OldHash {
			continue
		}
		// The backup does not hold this build's original. That is the normal
		// state after a game update: the backup is simply left over from the
		// previous build. If the live file is this build's untouched original
		// we can refresh the backup from it, which is done below. Anything
		// else means we cannot tell what the original was, so we stop.
		if it.st == stPatched {
			// Already patched, so there is nothing to install for this file
			// and nothing to lose by carrying on. The backup is stale, which
			// only matters when it comes time to undo or to re-port.
			continue
		}
		if it.st != stStock {
			fmt.Printf("%s: the existing backup is not the original, and %s is not this build's\n",
				filepath.Base(it.bak), filepath.Base(it.live))
			fmt.Println("untouched original either. Stopping, nothing changed.")
			fmt.Println("Verify the game files through Steam, then run this again.")
			return 1
		}
	}
	done := 0
	var noBackup []string
	for i := range items {
		it := &items[i]
		name := filepath.Base(it.live)
		if it.st == stPatched {
			b, err := os.ReadFile(it.bak)
			switch {
			case err != nil:
				fmt.Printf("  %-22s already patched, but there is no %s\n",
					name, filepath.Base(it.bak))
				noBackup = append(noBackup, name)
			case hashOf(b) != it.t.OldHash:
				fmt.Printf("  %-22s already patched, but %s is from an earlier build\n",
					name, filepath.Base(it.bak))
				noBackup = append(noBackup, name)
			default:
				fmt.Printf("  %-22s already patched, skipped\n", name)
			}
			continue
		}
		// Save the original, or refresh a backup left over from an earlier
		// build. Reaching here with a stale backup means the pre-check above
		// confirmed the live file is this build's untouched original.
		stale := false
		if b, err := os.ReadFile(it.bak); err != nil {
			stale = false
		} else if hashOf(b) != it.t.OldHash {
			stale = true
		}
		if _, err := os.Stat(it.bak); os.IsNotExist(err) || stale {
			if err := writeFile(it.bak, it.bytes); err != nil {
				fmt.Printf("  %-22s could not save the backup: %v\n", name, err)
				return 1
			}
			if stale {
				fmt.Printf("  %-22s backup was from an earlier build, refreshed\n", name)
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
		if it.st == stOlder {
			fmt.Printf("  %-22s updated from an earlier version of the patch\n", name)
		} else {
			fmt.Printf("  %-22s patched, original kept as %s\n", name, filepath.Base(it.bak))
		}
		done++
	}
	fmt.Println()
	fmt.Printf("Done: %d file(s) patched.\n", done)
	if len(noBackup) > 0 {
		fmt.Println()
		fmt.Printf("WARNING: %d file(s) are patched with no saved original:\n", len(noBackup))
		for _, n := range noBackup {
			fmt.Printf("    %s\n", n)
		}
		fmt.Println("This patch stores only the bytes it changes - the original bytes are")
		fmt.Println("deliberately not in it - so it cannot be undone from itself. With the")
		fmt.Println("backup gone, the way back is Steam: right-click Garry's Mod, Properties,")
		fmt.Println("Installed Files, Verify integrity of game files. Then run this again and")
		fmt.Println("the originals will be saved properly.")
		fmt.Println()
		fmt.Println("If you installed with something else that kept its own backups under")
		fmt.Println("different names, restoring with that tool first works too.")
	}
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
	code := run()
	waitIfOwnConsole()
	os.Exit(code)
}

func run() int {
	var (
		gmod     = flag.String("gmod", "", "path to the GarrysMod folder (found automatically if omitted)")
		doRest   = flag.Bool("restore", false, "put the original files back")
		doVer    = flag.Bool("verify", false, "only report what is currently installed")
		doList   = flag.Bool("list", false, "list the game builds this patcher has a patch for")
		showVer  = flag.Bool("version", false, "print version and exit")
		onlyMaps = flag.Bool("maps", false, "only install the maps found next to the patcher, do not touch the game files")
		noExtra  = flag.Bool("no-hammer", false, "leave Hammer++ alone")
		onlyComp = flag.Bool("compilers", false, "only install the map compilers found next to the patcher")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("gmod483k %s\n", version)
		return 0
	}
	fmt.Printf("gmod483k %s - big map patch for Garry's Mod\n", version)

	rels, err := loadReleases()
	if err != nil {
		fmt.Println(err)
		return 1
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
		return 0
	}

	root := *gmod
	if root == "" {
		root = FindGMod()
	}
	if root == "" {
		fmt.Println()
		fmt.Println("Could not find Garry's Mod. Pass the folder explicitly, for example:")
		fmt.Println(`  gmod483k -gmod "D:\SteamLibrary\steamapps\common\GarrysMod"`)
		return 1
	}
	if _, err := os.Stat(filepath.Join(root, "garrysmod", "gameinfo.txt")); err != nil {
		fmt.Printf("\n%s does not look like a GarrysMod folder.\n", root)
		return 1
	}
	fmt.Println("game: ", root)

	maps, mapsFrom := findMaps()
	if *onlyMaps {
		if len(maps) == 0 {
			fmt.Println()
			fmt.Println("No maps found next to the patcher. Put a 'maps' folder or a")
			fmt.Println("'maps.zip' containing .bsp files in the same directory as this")
			fmt.Println("program, then run it again.")
			return 1
		}
		fmt.Println()
		return installMaps(root, maps, mapsFrom)
	}

	tools, toolsFrom := findCompilers()
	if *onlyComp {
		if len(tools) == 0 {
			fmt.Println()
			fmt.Println("No compilers found next to the patcher. Put 'compilers.zip' from the")
			fmt.Println("release in the same directory as this program, then run it again.")
			return 1
		}
		fmt.Println()
		return installCompilers(root, tools, toolsFrom)
	}

	// Hammer++ does not depend on the game build, so it is handled whether
	// or not the game patch applies.
	extra := func(mode string) {
		if !*noExtra {
			optional(root, mode)
		}
	}
	mode := "install"
	switch {
	case *doVer:
		mode = "verify"
	case *doRest:
		mode = "restore"
	}

	rel, items, ok := pick(root, rels)
	if !ok {
		report(items)
		explainUnsupported(root, rels, items)
		extra(mode)
		if mode == "install" && len(tools) > 0 {
			fmt.Println()
			installCompilers(root, tools, toolsFrom)
		}
		return 1
	}
	fmt.Println("patch:", rel.patch.Note)
	report(items)

	switch {
	case *doVer:
		patched, stock, older := 0, 0, 0
		for _, it := range items {
			switch it.st {
			case stPatched:
				patched++
			case stStock:
				stock++
			case stOlder:
				older++
			}
		}
		switch {
		case older > 0 && older+patched == len(items):
			fmt.Println("An earlier version of the patch is installed. Run the patcher with no")
			fmt.Println("arguments to bring it up to date.")
		case patched == len(items):
			fmt.Println("The patch is fully installed.")
		case stock == len(items):
			fmt.Println("Everything is original. Run the patcher with no arguments to install.")
		default:
			fmt.Println("Mixed state. Run -restore, then install again.")
		}
		extra(mode)
	case *doRest:
		code := restore(items)
		extra(mode)
		return code
	default:
		if code := install(items); code != 0 {
			return code
		}
		extra(mode)
		if len(tools) > 0 {
			fmt.Println()
			if code := installCompilers(root, tools, toolsFrom); code != 0 {
				return code
			}
		}
		if len(maps) > 0 {
			fmt.Println()
			return installMaps(root, maps, mapsFrom)
		}
	}
	return 0
}
