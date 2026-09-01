package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mirzasaikatahmmed/gitshield/internal/git"
	"github.com/mirzasaikatahmmed/gitshield/internal/scanner"
)

func cmdPull(args []string) int {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	gf := parseCommonFlags(fs)
	remote := fs.String("remote", "origin", "remote to fetch from")
	if err := parseArgs(fs, args); err != nil {
		return 2
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}
	if !git.IsGitRepo(cwd) {
		fmt.Fprintln(os.Stderr, "gitshield: pull must be run inside an existing git repository")
		return 2
	}

	maybeAutoUpdate(*gf)

	eng, cfg, err := loadEngine(*gf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	repoURL, _ := git.RemoteURL(cwd, *remote)

	if cfg.IsAllowlisted(repoURL) || cfg.IsAllowlisted(cwd) {
		if err := git.Fetch(cwd, *remote); err != nil {
			fmt.Fprintln(os.Stderr, "gitshield: fetch failed:", err)
			return 2
		}
		if err := fastForward(cwd); err != nil {
			fmt.Fprintln(os.Stderr, "gitshield:", err)
			return 2
		}
		if !gf.jsonOut {
			fmt.Printf("gitshield: %s is allowlisted; pulled without scanning\n", repoURL)
		}
		return 0
	}

	// Fetch updates remote-tracking refs only — the working tree and local
	// branch are untouched until gitshield decides it's safe to merge.
	if err := git.Fetch(cwd, *remote); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: fetch failed:", err)
		return 2
	}

	upstream, err := git.UpstreamRef(cwd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: no upstream configured for the current branch:", err)
		return 2
	}

	res, scanErr := scanRef(eng, cwd, upstream)
	if scanErr != nil {
		fmt.Fprintln(os.Stderr, "gitshield: scan failed:", scanErr)
		return 2
	}

	d := decide(*gf, res, repoURL)
	logAudit("pull", repoURL, res, d)
	maybeShipToDashboard(*gf)
	emitReport(*gf, res, repoURL, d)

	if !d.proceed {
		if !gf.jsonOut {
			fmt.Fprintln(os.Stderr, "gitshield: pull aborted before merge; local branch untouched")
		}
		return d.exitCode
	}

	if err := git.FastForwardMerge(cwd, upstream); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: fast-forward failed (local branch may have diverged):", err)
		return 2
	}
	if !gf.jsonOut {
		fmt.Println("gitshield: fast-forwarded to", upstream)
	}
	return d.exitCode
}

func fastForward(repoDir string) error {
	upstream, err := git.UpstreamRef(repoDir)
	if err != nil {
		return fmt.Errorf("no upstream configured for the current branch: %w", err)
	}
	return git.FastForwardMerge(repoDir, upstream)
}

// scanRef scans every target file as it exists in ref's tree, without
// touching the working directory.
func scanRef(eng *scanner.Engine, repoDir, ref string) (scanner.Result, error) {
	var res scanner.Result

	paths, err := git.ListTreeFiles(repoDir, ref)
	if err != nil {
		return res, err
	}
	for _, p := range paths {
		if !scanner.IsScanTarget(p, eng.Deep) {
			continue
		}
		content, err := git.ShowBlob(repoDir, ref, p)
		if err != nil {
			continue
		}
		findings := eng.ScanBytes(p, content)
		res.FilesScanned++
		sev := eng.Severity(findings)
		if len(findings) > 0 {
			res.Files = append(res.Files, scanner.FileResult{Path: p, Findings: findings, Severity: sev})
		}
		if sev > res.Severity {
			res.Severity = sev
		}
	}
	return res, nil
}
