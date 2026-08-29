package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mirzasaikatahmmed/gitshield/internal/config"
	"github.com/mirzasaikatahmmed/gitshield/internal/platform"
)

// defaultInstallDir returns ~/.local/bin, the conventional user-writable
// bin directory that doesn't require sudo and is on PATH for most modern
// distro/shell defaults (falls back to a reasonable message if it isn't).
func defaultInstallDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/usr/local/bin"
	}
	return filepath.Join(home, ".local", "bin")
}

func cmdInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	gf := parseCommonFlags(fs)
	prefix := fs.String("prefix", defaultInstallDir(), "directory to install the gitshield binary into")
	if err := parseArgs(fs, args); err != nil {
		return 2
	}

	src, err := runningExecutablePath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: could not determine the running binary's path:", err)
		return 2
	}

	if err := os.MkdirAll(*prefix, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: creating", *prefix+":", err)
		return 2
	}
	dest := filepath.Join(*prefix, platform.InstalledName())

	if sameFile(src, dest) {
		if !gf.jsonOut {
			fmt.Printf("gitshield: already installed at %s\n", dest)
		}
	} else if err := copyExecutable(src, dest); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: installing to", dest+":", err)
		return 2
	} else if !gf.jsonOut {
		fmt.Printf("gitshield: installed -> %s\n", dest)
	}

	// Ensure ~/.gitshield exists up front so config/audit-log paths are
	// ready the first time a scan runs.
	if _, err := config.Dir(); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: warning: could not create ~/.gitshield:", err)
	}

	if !gf.jsonOut && !onPath(*prefix) {
		fmt.Printf("gitshield: NOTE: %s is not on your PATH. Add this to your shell profile:\n", *prefix)
		fmt.Printf("  export PATH=%q:\"$PATH\"\n", *prefix)
	}
	return 0
}

func onPath(dir string) bool {
	pathEnv := os.Getenv("PATH")
	for _, p := range filepath.SplitList(pathEnv) {
		if p == dir {
			return true
		}
	}
	return false
}

func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// copyExecutable copies src to dest atomically (write to a temp file in the
// destination directory, then rename over it) and marks it executable.
func copyExecutable(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".gitshield-install-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpPath, dest)
}

func cmdUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	gf := parseCommonFlags(fs)
	prefix := fs.String("prefix", "", "only remove the binary from this directory (default: search common install locations)")
	purge := fs.Bool("purge", false, "also remove ~/.gitshield (config, custom signatures, AND the audit log)")
	if err := parseArgs(fs, args); err != nil {
		return 2
	}

	candidates := []string{}
	if *prefix != "" {
		candidates = append(candidates, filepath.Join(*prefix, platform.InstalledName()))
	} else {
		candidates = append(candidates, filepath.Join(defaultInstallDir(), platform.InstalledName()), filepath.Join("/usr/local/bin", platform.InstalledName()))
		if exe, err := runningExecutablePath(); err == nil {
			candidates = append(candidates, exe)
		}
	}

	removed := map[string]bool{}
	for _, c := range candidates {
		if removed[c] {
			continue
		}
		if _, err := os.Stat(c); err != nil {
			continue
		}
		if err := os.Remove(c); err != nil {
			fmt.Fprintln(os.Stderr, "gitshield: removing", c+":", err)
			continue
		}
		removed[c] = true
		if !gf.jsonOut {
			fmt.Println("gitshield: removed", c)
		}
	}
	if len(removed) == 0 && !gf.jsonOut {
		fmt.Println("gitshield: no installed binary found in:", strings.Join(candidates, ", "))
	}

	dir, dirErr := config.Dir()
	if *purge && dirErr == nil {
		if gf.yes || confirmYesNo(fmt.Sprintf("Remove %s, including the audit log? [y/N] ", dir)) {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintln(os.Stderr, "gitshield: removing", dir+":", err)
				return 2
			}
			if !gf.jsonOut {
				fmt.Println("gitshield: removed", dir)
			}
		} else if !gf.jsonOut {
			fmt.Println("gitshield: kept", dir)
		}
	} else if !gf.jsonOut && dirErr == nil {
		fmt.Printf("gitshield: kept %s (config + audit log). Re-run with --purge to remove it.\n", dir)
	}

	return 0
}
