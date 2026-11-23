package main

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Map compilers.
//
// Like the maps, the compilers ship beside the patcher, not inside it: a
// "compilers.zip" or a "compilers" folder next to the executable. They are
// not game files and are not patched - they are complete programs, built from
// Valve's Source SDK 2013 and distributed under its licence, which travels
// with them in the archive. Installing them means copying the .exe files into
// bin\win64, where they find the game's own filesystem and physics libraries,
// and telling Hammer++ where they are.

type toolSrc struct {
	name string
	size int64
	open func() (io.ReadCloser, error)
}

// The three programs Hammer++ has a setting for, by the key it uses.
var hammerKeys = []struct{ key, prefix string }{
	{"BSP", "vbsp"},
	{"Vis", "vvis"},
	{"Light", "vrad"},
}

const hammerConfig = "hammerplusplus_gameconfig.txt"

func wantedTool(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".bat":
		return true
	}
	return false
}

func findCompilers() ([]toolSrc, string) {
	dir := exeDir()

	zipPath := filepath.Join(dir, "compilers.zip")
	if st, err := os.Stat(zipPath); err == nil && !st.IsDir() {
		if zr, err := zip.OpenReader(zipPath); err == nil {
			var out []toolSrc
			for _, f := range zr.File {
				// top level only: subfolders hold reference material
				if strings.ContainsAny(f.Name, `/\`) || !wantedTool(f.Name) {
					continue
				}
				fc := f
				out = append(out, toolSrc{
					name: fc.Name,
					size: int64(fc.UncompressedSize64),
					open: func() (io.ReadCloser, error) { return fc.Open() },
				})
			}
			if len(out) > 0 {
				sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
				return out, zipPath
			}
		}
	}

	src := filepath.Join(dir, "compilers")
	ents, err := os.ReadDir(src)
	if err != nil {
		return nil, ""
	}
	var out []toolSrc
	for _, e := range ents {
		if e.IsDir() || !wantedTool(e.Name()) {
			continue
		}
		full := filepath.Join(src, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, toolSrc{
			name: e.Name(),
			size: info.Size(),
			open: func() (io.ReadCloser, error) { return os.Open(full) },
		})
	}
	if len(out) == 0 {
		return nil, ""
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, src
}

// copyVerified writes src to target through a temporary file and reports
// whether anything changed.
func copyVerified(open func() (io.ReadCloser, error), target string) (changed bool, err error) {
	rc, err := open()
	if err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".gmod483k-*")
	if err != nil {
		rc.Close()
		return false, err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), rc)
	rc.Close()
	tmp.Close()
	if err != nil {
		os.Remove(tmp.Name())
		return false, err
	}
	var want [32]byte
	copy(want[:], h.Sum(nil))
	if have, ok := sumFile(target); ok && have == want {
		os.Remove(tmp.Name())
		return false, nil
	}
	os.Chmod(tmp.Name(), 0o755)
	if err := os.Rename(tmp.Name(), target); err != nil {
		os.Remove(tmp.Name())
		return false, err
	}
	return true, nil
}

// samePath compares two paths the way a person would: either kind of slash,
// doubled or not, any letter case, with or without a trailing one.
func samePath(a, b string) bool {
	norm := func(p string) string {
		p = strings.ReplaceAll(p, `\`, "/")
		for strings.Contains(p, "//") {
			p = strings.ReplaceAll(p, "//", "/")
		}
		return strings.ToLower(strings.TrimRight(p, "/"))
	}
	return norm(a) == norm(b)
}

var reConfigLine = regexp.MustCompile(`^(\s*"([^"]+)"\s+)"([^"]*)"(\s*)$`)

// pointHammer rewrites the BSP/Vis/Light entries of the Hammer++ game
// configuration that belongs to this game folder. Other games configured in
// the same file are left exactly as they are.
func pointHammer(root string, exes map[string]string) {
	gameDir := filepath.Join(root, "garrysmod")
	found := false
	for _, cfg := range findByName(root, hammerConfig) {
		found = true
		b, err := os.ReadFile(cfg)
		if err != nil {
			continue
		}
		nl := "\n"
		if strings.Contains(string(b), "\r\n") {
			nl = "\r\n"
		}
		lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
		ours, changed, seen := false, 0, 0
		for i, ln := range lines {
			m := reConfigLine.FindStringSubmatch(ln)
			if m == nil {
				continue
			}
			if strings.EqualFold(m[2], "GameDir") {
				ours = samePath(m[3], gameDir)
				continue
			}
			if !ours {
				continue
			}
			for _, hk := range hammerKeys {
				if !strings.EqualFold(m[2], hk.key) {
					continue
				}
				want, ok := exes[hk.prefix]
				if !ok {
					continue
				}
				seen++
				if !samePath(m[3], want) {
					lines[i] = m[1] + `"` + want + `"` + m[4]
					changed++
				}
			}
		}
		name := filepath.Base(cfg)
		switch {
		case seen == 0:
			fmt.Printf("  %-26s has no entry for this game folder, left alone\n", name)
		case changed == 0:
			fmt.Printf("  %-26s already points at these compilers\n", name)
		default:
			if _, err := os.Stat(cfg + ".stock"); os.IsNotExist(err) {
				if err := writeFile(cfg+".stock", b); err != nil {
					fmt.Printf("  %-26s could not save the backup: %v\n", name, err)
					continue
				}
			}
			if err := writeFile(cfg, []byte(strings.Join(lines, nl))); err != nil {
				fmt.Printf("  %-26s could not write: %v\n", name, err)
				continue
			}
			fmt.Printf("  %-26s build programs set, previous copy kept as %s.stock\n", name, name)
		}
	}
	if !found {
		fmt.Println()
		fmt.Println("Hammer++ has no game configuration yet. Once it has one, set these under")
		fmt.Println("Tools > Options > Build Programs:")
		for _, hk := range hammerKeys {
			if p, ok := exes[hk.prefix]; ok {
				fmt.Printf("  %-6s %s\n", hk.key+":", p)
			}
		}
	}
}

func installCompilers(root string, srcs []toolSrc, from string) int {
	bin := filepath.Join(root, "bin", "win64")
	if _, err := os.Stat(bin); err != nil {
		fmt.Printf("  %s is missing - the compilers need the 64-bit branch of the game\n", bin)
		return 1
	}
	fmt.Printf("compilers: %s\n", from)
	fmt.Println()
	exes := map[string]string{}
	launcher := ""
	for _, s := range srcs {
		dst := bin
		if strings.EqualFold(filepath.Ext(s.name), ".bat") {
			dst = root
		}
		target := filepath.Join(dst, s.name)
		changed, err := copyVerified(s.open, target)
		if err != nil {
			fmt.Printf("  %-26s could not write: %v\n", s.name, err)
			return 1
		}
		if changed {
			fmt.Printf("  %-26s installed\n", s.name)
		} else {
			fmt.Printf("  %-26s already there, unchanged\n", s.name)
		}
		low := strings.ToLower(s.name)
		if strings.HasSuffix(low, ".exe") {
			for _, hk := range hammerKeys {
				if strings.HasPrefix(low, hk.prefix) {
					exes[hk.prefix] = target
				}
			}
		} else if strings.HasPrefix(low, "hammer") {
			launcher = target
		}
	}
	pointHammer(root, exes)
	fmt.Println()
	fmt.Println("The compilers are built from Valve's Source SDK 2013; its licence is in the")
	fmt.Println("archive they came in.")
	if launcher != "" {
		fmt.Printf("Start Hammer++ with %s: it sets VPROJECT to this game,\n", filepath.Base(launcher))
		fmt.Println("which the light compiler needs to find the game's materials.")
	}
	return 0
}
