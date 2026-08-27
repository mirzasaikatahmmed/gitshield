package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mirzasaikatahmmed/gitshield/internal/git"
	"github.com/mirzasaikatahmmed/gitshield/internal/scanner"
)

func cmdAdd(args []string) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	gf := parseCommonFlags(fs)
	if err := parseArgs(fs, args); err != nil {
		return 2
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}
	if !git.IsGitRepo(cwd) {
		fmt.Fprintln(os.Stderr, "gitshield: add must be run inside an existing git repository")
		return 2
	}

	maybeAutoUpdate(*gf)

	eng, cfg, err := loadEngine(*gf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	repoURL, _ := git.RemoteURL(cwd, "origin")
	repoRef := repoURL
	if repoRef == "" {
		repoRef = cwd
	}

	gitAddArgs := fs.Args()
	if len(gitAddArgs) == 0 {
		gitAddArgs = []string{"."}
	}

	if cfg.IsAllowlisted(repoURL) || cfg.IsAllowlisted(cwd) {
		if err := git.Add(cwd, gitAddArgs); err != nil {
			fmt.Fprintln(os.Stderr, "gitshield:", err)
			return 2
		}
		if !gf.jsonOut {
			fmt.Printf("gitshield: %s is allowlisted; staged without scanning\n", repoRef)
		}
		return 0
	}

	paths, err := git.AddDryRunPaths(cwd, gitAddArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	res, err := scanStagedCandidates(eng, cwd, paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	d := decide(*gf, res, repoRef)
	logAudit("add", repoRef, res, d)
	emitReport(*gf, res, repoRef, d)

	if !d.proceed {
		if !gf.jsonOut {
			fmt.Fprintln(os.Stderr, "gitshield: add aborted; nothing staged")
		}
		return d.exitCode
	}

	if err := git.Add(cwd, gitAddArgs); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}
	if !gf.jsonOut {
		fmt.Println("gitshield: staged")
	}
	return d.exitCode
}

// scanStagedCandidates scans target files among paths that git add would stage.
func scanStagedCandidates(eng *scanner.Engine, repoDir string, paths []string) (scanner.Result, error) {
	var res scanner.Result
	for _, rel := range paths {
		if !scanner.IsTargetFile(rel) {
			continue
		}
		full := filepath.Join(repoDir, rel)
		fr, err := eng.ScanFile(full)
		if err != nil {
			return res, fmt.Errorf("scan %s: %w", rel, err)
		}
		fr.Path = rel
		res.FilesScanned++
		if len(fr.Findings) > 0 {
			res.Files = append(res.Files, fr)
		}
		if fr.Severity > res.Severity {
			res.Severity = fr.Severity
		}
	}
	return res, nil
}
