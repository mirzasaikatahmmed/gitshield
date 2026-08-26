package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/mirzasaikatahmmed/gitshield/internal/selfupdate"
)

// cmdUpdate self-updates the gitshield binary in place: checks the GitHub
// Releases API for a newer tag than the running version, downloads the
// release asset matching this OS/arch, verifies it against the published
// checksum, and atomically replaces the currently running executable.
//
// This is distinct from `update-signatures`, which only refreshes the IOC
// signature set — this command replaces gitshield itself.
func cmdUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	gf := parseCommonFlags(fs)
	checkOnly := fs.Bool("check", false, "check for a newer version without installing it")
	force := fs.Bool("force", false, "reinstall even if already on the latest version")
	repo := fs.String("repo", selfupdate.DefaultRepo, "GitHub owner/repo to check for releases")
	if err := parseArgs(fs, args); err != nil {
		return 2
	}

	rel, err := selfupdate.FetchLatest(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: checking for updates:", err)
		return 2
	}

	newer := selfupdate.IsNewer(rel.TagName, version)
	if !newer && !*force {
		if gf.jsonOut {
			fmt.Printf("{\"current\":%q,\"latest\":%q,\"update_available\":false}\n", version, rel.TagName)
		} else {
			fmt.Printf("gitshield: already up to date (v%s)\n", version)
		}
		return 0
	}

	if *checkOnly {
		if gf.jsonOut {
			fmt.Printf("{\"current\":%q,\"latest\":%q,\"update_available\":true}\n", version, rel.TagName)
		} else {
			fmt.Printf("gitshield: update available: v%s -> %s\n", version, rel.TagName)
			fmt.Println("gitshield: run `gitshield update` to install it")
		}
		return 0
	}

	tarAsset, sumAsset, err := selfupdate.FindAssets(rel, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	const maxBinaryBytes = 200 * 1024 * 1024
	tarData, err := selfupdate.Download(tarAsset.URL, maxBinaryBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: downloading", tarAsset.Name+":", err)
		return 2
	}
	sumData, err := selfupdate.Download(sumAsset.URL, 4096)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: downloading", sumAsset.Name+":", err)
		return 2
	}
	if err := selfupdate.VerifyChecksum(tarData, sumData, tarAsset.Name); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: SIGNATURE/CHECKSUM VERIFICATION FAILED — refusing to install:", err)
		return 2
	}

	binName := fmt.Sprintf("gitshield-%s-%s", runtime.GOOS, runtime.GOARCH)
	binData, err := selfupdate.ExtractFile(tarData, binName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: extracting release archive:", err)
		return 2
	}

	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: could not determine the running binary's path:", err)
		return 2
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}

	if err := replaceExecutable(execPath, binData); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: installing update:", err)
		fmt.Fprintln(os.Stderr, "gitshield: if this is a permission error, retry with sudo (or a write-permitted install path)")
		return 2
	}

	if gf.jsonOut {
		fmt.Printf("{\"previous\":%q,\"installed\":%q,\"path\":%q}\n", version, rel.TagName, execPath)
	} else {
		fmt.Printf("gitshield: updated v%s -> %s (%s)\n", version, rel.TagName, execPath)
	}
	return 0
}

// replaceExecutable atomically overwrites target with data: write to a temp
// file in the same directory (so the rename is on the same filesystem),
// mark it executable, then rename over target. Safe to do to a currently
// running binary on POSIX systems — the running process keeps its already
// -open inode; the new file only takes effect on the next invocation.
func replaceExecutable(target string, data []byte) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".gitshield-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}
