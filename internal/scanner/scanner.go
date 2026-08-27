// Package scanner implements the config-file malware detection engine:
// matching known IOC signatures and behavioral heuristics against target
// files (eslint/postcss/prettier/tailwind configs, .eslintrc*, .gitignore).
package scanner

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/mirzasaikatahmmed/gitshield/internal/signatures"
)

// Severity is the aggregate risk level of a scan or a single file's findings.
type Severity int

const (
	Clean Severity = iota
	Moderate
	High
)

func (s Severity) String() string {
	switch s {
	case Clean:
		return "CLEAN"
	case Moderate:
		return "MODERATE"
	case High:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// Finding is a single signature/heuristic match.
type Finding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	SignatureID string `json:"signature_id"`
	Kind        string `json:"kind"` // "exact" or "heuristic"
	Description string `json:"description"`
	Excerpt     string `json:"excerpt"`
	// Ref is set when the finding came from git history scanning: the
	// commit hash the match was found in, rather than the working tree.
	Ref string `json:"ref,omitempty"`
}

// FileResult aggregates findings for a single file plus its computed severity.
type FileResult struct {
	Path     string    `json:"path"`
	Findings []Finding `json:"findings"`
	Severity Severity  `json:"severity"`
}

// Result is the outcome of scanning a directory tree (or a set of files).
type Result struct {
	FilesScanned int          `json:"files_scanned"`
	Files        []FileResult `json:"files"`
	Severity     Severity     `json:"severity"`
}

// Thresholds controls how many heuristic hits in a single file escalate
// severity. Defaults match the spec: 1 heuristic hit => MODERATE,
// 2+ heuristic hits (or any exact match) => HIGH.
type Thresholds struct {
	HighHeuristicCount int
}

func DefaultThresholds() Thresholds {
	return Thresholds{HighHeuristicCount: 2}
}

// Engine runs scans using a fixed signature set and severity thresholds.
type Engine struct {
	Sigs       signatures.Set
	Thresholds Thresholds
}

func NewEngine(sigs signatures.Set) *Engine {
	return &Engine{Sigs: sigs, Thresholds: DefaultThresholds()}
}

// ScanBytes scans in-memory file content against all configured signatures
// and heuristics, returning findings ordered by line number.
func (e *Engine) ScanBytes(path string, content []byte) []Finding {
	if f := wormArtifactFinding(path); f != nil {
		return []Finding{*f}
	}

	var findings []Finding

	lines := splitLines(content)
	text := string(content)

	for _, sig := range e.Sigs.Signatures {
		switch sig.Kind {
		case signatures.KindString:
			findings = append(findings, matchString(path, lines, sig)...)
		case signatures.KindRegex:
			findings = append(findings, matchRegex(path, lines, sig)...)
		case signatures.KindHeuristic:
			findings = append(findings, runHeuristic(path, lines, text, sig)...)
		}
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Line < findings[j].Line })
	return findings
}

// Severity computes the severity of a file's findings per the spec:
//   - any exact match => HIGH
//   - 2+ heuristic hits => HIGH
//   - exactly 1 heuristic hit (and no exact match) => MODERATE
//   - no findings => CLEAN
func (e *Engine) Severity(findings []Finding) Severity {
	exact := 0
	heuristic := 0
	for _, f := range findings {
		if f.Kind == "exact" {
			exact++
		} else {
			heuristic++
		}
	}
	switch {
	case exact > 0:
		return High
	case heuristic >= e.Thresholds.HighHeuristicCount:
		return High
	case heuristic >= 1:
		return Moderate
	default:
		return Clean
	}
}

// ScanFile reads and scans a single file from disk.
func (e *Engine) ScanFile(path string) (FileResult, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return FileResult{}, err
	}
	findings := e.ScanBytes(path, content)
	return FileResult{
		Path:     path,
		Findings: findings,
		Severity: e.Severity(findings),
	}, nil
}

// ScanDir walks root, scanning every file that IsTargetFile matches.
// Directories named .git are skipped (git history is scanned separately
// via the --history flag / ScanGitHistory in internal/git).
func (e *Engine) ScanDir(root string) (Result, error) {
	var res Result

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if !IsTargetFile(rel) {
			return nil
		}
		fr, scanErr := e.ScanFile(path)
		if scanErr != nil {
			// Unreadable file (permissions, broken symlink, etc.) — skip
			// rather than aborting the whole scan.
			return nil
		}
		fr.Path = rel
		res.FilesScanned++
		if len(fr.Findings) > 0 {
			res.Files = append(res.Files, fr)
		}
		if fr.Severity > res.Severity {
			res.Severity = fr.Severity
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}

	sort.Slice(res.Files, func(i, j int) bool { return res.Files[i].Path < res.Files[j].Path })
	return res, nil
}

func splitLines(content []byte) [][]byte {
	var lines [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // allow long packed lines
	for scanner.Scan() {
		b := scanner.Bytes()
		cp := make([]byte, len(b))
		copy(cp, b)
		lines = append(lines, cp)
	}
	return lines
}
