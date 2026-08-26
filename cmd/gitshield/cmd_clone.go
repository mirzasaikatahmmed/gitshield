package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mirzasaikatahmmed/gitshield/internal/git"
	"github.com/mirzasaikatahmmed/gitshield/internal/report"
)

func cmdClone(args []string) int {
	fs := flag.NewFlagSet("clone", flag.ContinueOnError)
	gf := parseCommonFlags(fs)
	dest := fs.String("dest", "", "destination directory (default: derived from the repo URL, like git clone)")
	if err := parseArgs(fs, args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "gitshield: clone requires a <repo-url>")
		return 2
	}
	repoURL := fs.Arg(0)

	maybeAutoUpdate(*gf)

	eng, cfg, err := loadEngine(*gf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	destDir := *dest
	if destDir == "" {
		destDir = git.DeriveDestDir(repoURL)
	}

	// Every clone — allowlisted or not — goes through the quarantine
	// directory first; it never touches the real working tree until
	// gitshield decides it's safe. For an allowlisted repo the scan step
	// below is simply skipped before moving into place.
	quarantineDir, err := git.CloneQuarantine(repoURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: clone failed:", err)
		return 2
	}

	if cfg.IsAllowlisted(repoURL) {
		if err := git.MoveIntoPlace(quarantineDir, destDir); err != nil {
			_ = git.RemoveQuarantine(quarantineDir)
			fmt.Fprintln(os.Stderr, "gitshield: failed to finalize clone:", err)
			return 2
		}
		if !gf.jsonOut {
			fmt.Printf("gitshield: %s is allowlisted; cloned without scanning -> %s\n", repoURL, destDir)
		}
		return report.ExitClean
	}

	res, scanErr := eng.ScanDir(quarantineDir)
	if scanErr != nil {
		_ = git.RemoveQuarantine(quarantineDir)
		fmt.Fprintln(os.Stderr, "gitshield: scan failed:", scanErr)
		return 2
	}

	d := decide(*gf, res, repoURL)
	logAudit("clone", repoURL, res, d)
	emitReport(*gf, res, repoURL, d)

	if !d.proceed {
		_ = git.RemoveQuarantine(quarantineDir)
		if !gf.jsonOut {
			fmt.Fprintln(os.Stderr, "gitshield: clone aborted; quarantine directory removed")
		}
		return d.exitCode
	}

	if err := git.MoveIntoPlace(quarantineDir, destDir); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: failed to finalize clone:", err)
		return 2
	}
	if !gf.jsonOut {
		fmt.Printf("gitshield: cloned %s -> %s\n", repoURL, destDir)
	}
	return d.exitCode
}
