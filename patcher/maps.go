package main

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Maps are shipped beside the patcher rather than inside it: they are tens of
// megabytes, and someone who only wants the patch should not have to download
// them. A "maps" folder or a "maps.zip" next to the executable is picked up
// automatically.

type mapSrc struct {
	name string // bsp file name
	size int64
	open func() (io.ReadCloser, error)
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

func findMaps() ([]mapSrc, string) {
	dir := exeDir()

	zipPath := filepath.Join(dir, "maps.zip")
	if st, err := os.Stat(zipPath); err == nil && !st.IsDir() {
		zr, err := zip.OpenReader(zipPath)
		if err == nil {
			var out []mapSrc
			for _, f := range zr.File {
				if !strings.EqualFold(filepath.Ext(f.Name), ".bsp") {
					continue
				}
				fc := f
				out = append(out, mapSrc{
					name: filepath.Base(fc.Name),
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

	mapDir := filepath.Join(dir, "maps")
	ents, err := os.ReadDir(mapDir)
	if err != nil {
		return nil, ""
	}
	var out []mapSrc
	for _, e := range ents {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".bsp") {
			continue
		}
		full := filepath.Join(mapDir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, mapSrc{
			name: e.Name(),
			size: info.Size(),
			open: func() (io.ReadCloser, error) { return os.Open(full) },
		})
	}
	if len(out) == 0 {
		return nil, ""
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, mapDir
}

func sumFile(p string) ([32]byte, bool) {
	f, err := os.Open(p)
	if err != nil {
		return [32]byte{}, false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, true
}

func installMaps(root string, srcs []mapSrc, from string) int {
	dst := filepath.Join(root, "garrysmod", "maps")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		fmt.Printf("  could not reach %s: %v\n", dst, err)
		return 1
	}
	fmt.Printf("maps:   %s\n", from)
	fmt.Println()
	copied, skipped := 0, 0
	for _, m := range srcs {
		target := filepath.Join(dst, m.name)

		rc, err := m.open()
		if err != nil {
			fmt.Printf("  %-26s cannot read it: %v\n", m.name, err)
			return 1
		}
		tmp, err := os.CreateTemp(dst, ".gmod483k-map-*")
		if err != nil {
			rc.Close()
			fmt.Printf("  %-26s %v\n", m.name, err)
			return 1
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(tmp, h), rc)
		rc.Close()
		tmp.Close()
		if err != nil {
			os.Remove(tmp.Name())
			fmt.Printf("  %-26s %v\n", m.name, err)
			return 1
		}
		var want [32]byte
		copy(want[:], h.Sum(nil))

		if have, ok := sumFile(target); ok && have == want {
			os.Remove(tmp.Name())
			fmt.Printf("  %-26s already there, unchanged\n", m.name)
			skipped++
			continue
		}
		os.Chmod(tmp.Name(), 0o644)
		if err := os.Rename(tmp.Name(), target); err != nil {
			os.Remove(tmp.Name())
			fmt.Printf("  %-26s could not write: %v\n", m.name, err)
			return 1
		}
		fmt.Printf("  %-26s installed, %.1f MB\n", m.name, float64(m.size)/(1024*1024))
		copied++
	}
	fmt.Println()
	fmt.Printf("%d map(s) installed, %d already present.\n", copied, skipped)
	if copied+skipped > 0 {
		fmt.Println("Open them from the main menu, or with:  map <name>")
	}
	return 0
}
