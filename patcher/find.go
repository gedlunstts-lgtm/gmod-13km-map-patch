package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var libRe = regexp.MustCompile(`"path"\s*"([^"]+)"`)

// steamFromRegistry asks Windows where Steam is, which beats guessing.
// Anything unexpected - another OS, no reg.exe, no such key - just yields
// nothing and the guesses below take over.
func steamFromRegistry() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	var out []string
	for _, key := range []string{
		`HKCU\Software\Valve\Steam`,
		`HKLM\SOFTWARE\WOW6432Node\Valve\Steam`,
		`HKLM\SOFTWARE\Valve\Steam`,
	} {
		for _, val := range []string{"SteamPath", "InstallPath"} {
			b, err := exec.Command("reg", "query", key, "/v", val).Output()
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				i := strings.Index(line, "REG_SZ")
				if i < 0 {
					continue
				}
				p := strings.TrimSpace(line[i+len("REG_SZ"):])
				if p != "" {
					out = append(out, filepath.FromSlash(p))
				}
			}
		}
	}
	return out
}

func steamRoots() []string {
	roots := steamFromRegistry()
	add := func(p string) {
		if p != "" {
			roots = append(roots, p)
		}
	}
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles"} {
		if v := os.Getenv(env); v != "" {
			add(filepath.Join(v, "Steam"))
		}
	}
	for _, d := range []string{"C", "D", "E", "F", "G"} {
		add(d + `:\Steam`)
		add(d + `:\SteamLibrary`)
		add(d + `:\Games\Steam`)
	}
	return roots
}

// FindGMod returns the GarrysMod folder, or "" if it could not be located.
// Steam's own library list is the reliable part: one known Steam folder is
// enough to learn about every other drive the user keeps games on.
func FindGMod() string {
	var cands []string
	for _, root := range steamRoots() {
		cands = append(cands, filepath.Join(root, "steamapps", "common", "GarrysMod"))
		b, err := os.ReadFile(filepath.Join(root, "steamapps", "libraryfolders.vdf"))
		if err != nil {
			continue
		}
		for _, m := range libRe.FindAllStringSubmatch(string(b), -1) {
			lib := strings.ReplaceAll(m[1], `\\`, `\`)
			cands = append(cands, filepath.Join(lib, "steamapps", "common", "GarrysMod"))
		}
	}
	for _, c := range cands {
		if _, err := os.Stat(filepath.Join(c, "garrysmod", "gameinfo.txt")); err == nil {
			return c
		}
	}
	return ""
}
