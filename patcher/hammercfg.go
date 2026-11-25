package main

// Hammer++ game configuration.
//
// Hammer++ keeps its list of games in hammerplusplus_gameconfig.txt next to
// its FGD. The entry for Garry's Mod tells it where the game folder is (the
// one with gameinfo.txt), where the FGD and the compilers are, and where
// finished maps go. A fresh Hammer++ may have no such file yet, and a copy
// handed over from another computer carries that computer's paths: either way
// the compilers are started without a usable game folder and stop at
// "could not find gameinfo.txt". So the patcher writes the entry itself:
// creates it when it is missing, repoints it when its paths do not exist on
// this computer, and leaves alone anything that already works.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type kvNode struct {
	key      string
	value    string
	children []*kvNode
	block    bool
}

func (n *kvNode) child(key string) *kvNode {
	for _, c := range n.children {
		if strings.EqualFold(c.key, key) {
			return c
		}
	}
	return nil
}

func (n *kvNode) get(key string) string {
	if c := n.child(key); c != nil && !c.block {
		return c.value
	}
	return ""
}

func (n *kvNode) set(key, value string) {
	if c := n.child(key); c != nil && !c.block {
		c.value = value
		return
	}
	n.children = append(n.children, &kvNode{key: key, value: value})
}

func (n *kvNode) sub(key string) *kvNode {
	if c := n.child(key); c != nil && c.block {
		return c
	}
	c := &kvNode{key: key, block: true}
	n.children = append(n.children, c)
	return c
}

// parseKV reads the KeyValues text Hammer writes: quoted or bare tokens,
// braces, // comments. Returns nil if the text does not parse.
func parseKV(text string) *kvNode {
	var toks []string
	i := 0
	for i < len(text) {
		c := text[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '/' && i+1 < len(text) && text[i+1] == '/':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '{' || c == '}':
			toks = append(toks, string(c))
			i++
		case c == '"':
			j := i + 1
			for j < len(text) && text[j] != '"' {
				j++
			}
			toks = append(toks, "\x00"+text[i+1:min(j, len(text))])
			i = j + 1
		default:
			j := i
			for j < len(text) && !strings.ContainsRune(" \t\r\n{}\"", rune(text[j])) {
				j++
			}
			toks = append(toks, "\x00"+text[i:j])
			i = j
		}
	}
	root := &kvNode{block: true}
	stack := []*kvNode{root}
	for k := 0; k < len(toks); k++ {
		t := toks[k]
		cur := stack[len(stack)-1]
		if t == "}" {
			if len(stack) == 1 {
				return nil
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if t == "{" {
			return nil
		}
		key := t[1:]
		if k+1 >= len(toks) {
			return nil
		}
		nx := toks[k+1]
		if nx == "{" {
			n := &kvNode{key: key, block: true}
			cur.children = append(cur.children, n)
			stack = append(stack, n)
			k++
		} else if nx == "}" {
			return nil
		} else {
			cur.children = append(cur.children, &kvNode{key: key, value: nx[1:]})
			k++
		}
	}
	if len(stack) != 1 {
		return nil
	}
	return root
}

func writeKV(sb *strings.Builder, n *kvNode, depth int, nl string) {
	ind := strings.Repeat("\t", depth)
	for _, c := range n.children {
		if c.block {
			sb.WriteString(ind + `"` + c.key + `"` + nl + ind + "{" + nl)
			writeKV(sb, c, depth+1, nl)
			sb.WriteString(ind + "}" + nl)
		} else {
			sb.WriteString(ind + `"` + c.key + `"		"` + c.value + `"` + nl)
		}
	}
}

func exists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if exists(p) {
			return p
		}
	}
	return paths[0]
}

// hammerDir is the Hammer++ data folder: where its FGD lives.
func hammerDir(root string) string {
	if f := findByName(root, hammerFGD); len(f) > 0 {
		return filepath.Dir(f[0])
	}
	d := filepath.Join(root, "bin", "win64", "hammerplusplus")
	if exists(filepath.Join(root, "bin", "win64", "hammerplusplus.exe")) && exists(d) {
		return d
	}
	return ""
}

// compilerPaths returns the compilers Hammer++ should run: the ones just
// installed if given, otherwise the 483k builds if they are in bin\win64,
// otherwise the game's own.
func compilerPaths(root string, exes map[string]string) map[string]string {
	bin := filepath.Join(root, "bin", "win64")
	out := map[string]string{}
	for _, hk := range hammerKeys {
		if p, ok := exes[hk.prefix]; ok {
			out[hk.key] = p
			continue
		}
		out[hk.key] = firstExisting(filepath.Join(bin, hk.prefix+"_483k.exe"), filepath.Join(bin, hk.prefix+".exe"))
	}
	return out
}

func fixHammerConfig(root string, exes map[string]string) {
	dir := hammerDir(root)
	if dir == "" {
		return
	}
	cfg := filepath.Join(dir, hammerConfig)
	gameDir := filepath.Join(root, "garrysmod")
	bin := filepath.Join(root, "bin", "win64")
	comp := compilerPaths(root, exes)

	orig, readErr := os.ReadFile(cfg)
	nl := "\r\n"
	var tree *kvNode
	if readErr == nil {
		if !strings.Contains(string(orig), "\r\n") {
			nl = "\n"
		}
		tree = parseKV(string(orig))
		if tree == nil {
			fmt.Printf("  %-28s could not be read, left alone\n", hammerConfig)
			return
		}
	} else {
		tree = &kvNode{block: true}
	}

	games := tree.sub("Configs").sub("Games")
	// The entry to use: the one for this game folder; failing that, one whose
	// game folder does not exist here (copied from another computer);
	// failing that, a new one.
	var game *kvNode
	for _, g := range games.children {
		if g.block && samePath(g.get("GameDir"), gameDir) {
			game = g
			break
		}
	}
	if game == nil {
		for _, g := range games.children {
			if g.block && !exists(filepath.Join(g.get("GameDir"), "gameinfo.txt")) {
				game = g
				break
			}
		}
	}
	if game == nil {
		name := "Garry's Mod"
		if games.child(name) != nil {
			name = "Garry's Mod 483k"
		}
		game = games.sub(name)
	}
	changed := 0
	set := func(n *kvNode, key, want string, keepIfExists bool) {
		cur := n.get(key)
		if keepIfExists && exists(cur) {
			return
		}
		if samePath(cur, want) && cur != "" {
			return
		}
		n.set(key, want)
		changed++
	}

	mapSrc := firstExisting(filepath.Join(root, "sourcesdk_content", "garrysmod", "mapsrc"), filepath.Join(root, "mapsrc"))
	prefabs := filepath.Join(bin, "Prefabs")

	set(game, "GameDir", gameDir, false)
	h := game.sub("Hammer")
	def := func(key, value string) {
		if h.get(key) == "" {
			h.set(key, value)
			changed++
		}
	}
	set(h, "GameData0", firstExisting(filepath.Join(root, "bin", "garrysmod.fgd"), filepath.Join(gameDir, "garrysmod.fgd")), true)
	def("TextureFormat", "5")
	def("MapFormat", "4")
	def("DefaultTextureScale", "0.250000")
	def("DefaultLightmapScale", "16")
	set(h, "GameExe", firstExisting(filepath.Join(root, "hl2.exe"), filepath.Join(root, "gmod.exe"), filepath.Join(bin, "gmod.exe")), true)
	def("DefaultSolidEntity", "func_detail")
	def("DefaultPointEntity", "info_player_start")
	for _, hk := range hammerKeys {
		set(h, hk.key, comp[hk.key], false)
	}
	set(h, "MDL", filepath.Join(bin, "studiomdl.exe"), true)
	set(h, "GameExeDir", root, true)
	set(h, "MapDir", mapSrc, true)
	set(h, "BSPDir", filepath.Join(gameDir, "maps"), true)
	set(h, "PrefabDir", prefabs, true)
	def("CordonTexture", `tools\toolsskybox`)
	def("MaterialExcludeCount", "0")
	if tree.child("Configs").get("SDKVersion") == "" {
		tree.child("Configs").set("SDKVersion", "5")
	}

	if changed == 0 {
		fmt.Printf("  %-28s already set up for this game\n", hammerConfig)
		return
	}
	for _, d := range []string{h.get("MapDir"), h.get("PrefabDir")} {
		if d != "" && !exists(d) {
			os.MkdirAll(d, 0o755)
		}
	}
	var sb strings.Builder
	writeKV(&sb, tree, 0, nl)
	if readErr == nil {
		if _, err := os.Stat(cfg + ".stock"); os.IsNotExist(err) {
			if err := writeFile(cfg+".stock", orig); err != nil {
				fmt.Printf("  %-28s could not save the backup: %v\n", hammerConfig, err)
				return
			}
		}
	}
	if err := writeFile(cfg, []byte(sb.String())); err != nil {
		fmt.Printf("  %-28s could not write (is Hammer++ running?): %v\n", hammerConfig, err)
		return
	}
	if readErr == nil {
		fmt.Printf("  %-28s paths set for this game, previous copy kept as %s.stock\n", hammerConfig, hammerConfig)
	} else {
		fmt.Printf("  %-28s created with the paths of this game\n", hammerConfig)
	}
	fmt.Printf("  %-28s game folder: %s\n", "", gameDir)
	fmt.Printf("  %-28s compilers:   %s\n", "", filepath.Dir(comp["BSP"]))
}

// fixSequences makes every "Run Map" sequence pass -blocksize 8192 to the
// BSP compiler. Without it vbsp_483k splits a big map into so many blocks that
// "Building Physics collision data" looks like a hang. Hammer++ copies the
// _default file the first time it runs, so both are done.
func fixSequences(root string) {
	dir := hammerDir(root)
	if dir == "" {
		return
	}
	for _, name := range []string{"hammerplusplus_sequences.cfg", "hammerplusplus_sequences_default.cfg"} {
		p := filepath.Join(dir, name)
		orig, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		tree := parseKV(string(orig))
		if tree == nil {
			fmt.Printf("  %-28s could not be read, left alone\n", name)
			continue
		}
		changed := 0
		var walk func(n *kvNode)
		walk = func(n *kvNode) {
			for _, c := range n.children {
				if !c.block {
					continue
				}
				if strings.EqualFold(c.get("run"), "$bsp_exe") {
					parms := c.get("parms")
					if !strings.Contains(strings.ToLower(parms), "-blocksize") {
						c.set("parms", strings.TrimSpace("-blocksize 8192 "+parms))
						changed++
					}
					continue
				}
				walk(c)
			}
		}
		walk(tree)
		if changed == 0 {
			fmt.Printf("  %-28s already passes -blocksize 8192\n", name)
			continue
		}
		nl := "\n"
		if strings.Contains(string(orig), "\r\n") {
			nl = "\r\n"
		}
		var sb strings.Builder
		writeKV(&sb, tree, 0, nl)
		if _, err := os.Stat(p + ".stock"); os.IsNotExist(err) {
			if err := writeFile(p+".stock", orig); err != nil {
				fmt.Printf("  %-28s could not save the backup: %v\n", name, err)
				continue
			}
		}
		if err := writeFile(p, []byte(sb.String())); err != nil {
			fmt.Printf("  %-28s could not write (is Hammer++ running?): %v\n", name, err)
			continue
		}
		fmt.Printf("  %-28s -blocksize 8192 added to %d compile step(s)\n", name, changed)
	}
}

// warnVproject reports a system-wide VPROJECT that points at a folder with no
// gameinfo.txt: vrad then looks for the game in the wrong place.
func warnVproject() {
	vp := os.Getenv("VPROJECT")
	if vp == "" || exists(filepath.Join(vp, "gameinfo.txt")) {
		return
	}
	fmt.Println()
	fmt.Printf("Note: the VPROJECT environment variable is set to %s,\n", vp)
	fmt.Println("which has no gameinfo.txt. The light compiler may then fail to find the")
	fmt.Println("game. Start Hammer++ with HAMMER483.bat, or remove VPROJECT in Windows")
	fmt.Println("settings (Environment Variables).")
}
