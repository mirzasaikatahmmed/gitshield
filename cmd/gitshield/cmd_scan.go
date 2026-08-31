package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mirzasaikatahmmed/gitshield/internal/git"
	"github.com/mirzasaikatahmmed/gitshield/internal/report"
	"github.com/mirzasaikatahmmed/gitshield/internal/scanner"
)

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	gf := parseCommonFlags(fs)
	history := fs.Bool("history", false, "also walk recent git history for target files")
	historyLimit := fs.Int("history-limit", 200, "max commits to walk with --history")
	if err := parseArgs(fs, args); err != nil {
		return 2
	}

	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	maybeAutoUpdate(*gf)

	eng, _, err := loadEngine(*gf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	res, err := eng.ScanDir(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: scan failed:", err)
		return 2
	}

	if *history {
		if !git.IsGitRepo(path) {
			fmt.Fprintln(os.Stderr, "gitshield: --history requires", path, "to be a git repository")
			return 2
		}
		histRes, err := scanHistory(eng, path, *historyLimit)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gitshield: history scan failed:", err)
			return 2
		}
		res = mergeResults(res, histRes)
	}

	if gf.jsonOut {
		exit := severityExitCode(res.Severity)
		_ = report.PrintJSON(os.Stdout, res, res.Severity != scanner.High, false, exit)
		return exit
	}

	report.PrintHuman(os.Stdout, res, path)
	return severityExitCode(res.Severity)
}

func severityExitCode(sev scanner.Severity) int {
	switch sev {
	case scanner.Clean:
		return report.ExitClean
	case scanner.Moderate:
		return report.ExitModerateProceeded
	case scanner.High:
		return report.ExitHighBlocked
	default:
		return report.ExitHighBlocked
	}
}

// scanHistory walks up to limit commits touching target files and scans the
// blob content of each target file as it existed at that commit.
func scanHistory(eng *scanner.Engine, repoDir string, limit int) (scanner.Result, error) {
	var res scanner.Result

	hashes, err := git.ListCommits(repoDir, scanner.TargetPathspecs(), limit)
	if err != nil {
		return res, err
	}

	seenFileSeverity := map[string]scanner.Severity{}
	fileFindings := map[string][]scanner.Finding{}

	for _, hash := range hashes {
		paths, err := git.ListTreeFiles(repoDir, hash)
		if err != nil {
			continue // commit may be unreachable/corrupt; skip rather than abort
		}
		for _, p := range paths {
			if !scanner.IsScanTarget(p, eng.Deep) {
				continue
			}
			content, err := git.ShowBlob(repoDir, hash, p)
			if err != nil {
				continue
			}
			findings := eng.ScanBytes(p, content)
			if len(findings) == 0 {
				continue
			}
			for i := range findings {
				findings[i].Ref = hash
			}
			key := hash + ":" + p
			fileFindings[key] = findings
			sev := eng.Severity(findings)
			seenFileSeverity[key] = sev
			if sev > res.Severity {
				res.Severity = sev
			}
			res.FilesScanned++
		}
	}

	for key, findings := range fileFindings {
		res.Files = append(res.Files, scanner.FileResult{
			Path:     key,
			Findings: findings,
			Severity: seenFileSeverity[key],
		})
	}
	return res, nil
}

func mergeResults(a, b scanner.Result) scanner.Result {
	out := a
	out.FilesScanned += b.FilesScanned
	out.Files = append(out.Files, b.Files...)
	if b.Severity > out.Severity {
		out.Severity = b.Severity
	}
	return out
}
