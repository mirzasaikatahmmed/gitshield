package scanner

import (
	"testing"

	"github.com/mirzasaikatahmmed/gitshield/internal/signatures"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	sigs, err := signatures.Default()
	if err != nil {
		t.Fatalf("loading default signatures: %v", err)
	}
	return NewEngine(sigs)
}

func TestCleanFixturesScoreClean(t *testing.T) {
	e := newTestEngine(t)
	res, err := e.ScanDir("testdata/clean")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if res.Severity != Clean {
		t.Fatalf("expected CLEAN, got %s (files with findings: %+v)", res.Severity, res.Files)
	}
	if res.FilesScanned == 0 {
		t.Fatalf("expected at least one target file to be scanned")
	}
	if len(res.Files) != 0 {
		t.Fatalf("expected no findings in clean fixtures, got %+v", res.Files)
	}
}

func TestInfectedEslintConfigIsHighViaExactMatch(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/infected/eslint.config.mjs")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if fr.Severity != High {
		t.Fatalf("expected HIGH, got %s", fr.Severity)
	}
	foundExact := false
	for _, f := range fr.Findings {
		if f.Kind == "exact" {
			foundExact = true
		}
	}
	if !foundExact {
		t.Fatalf("expected at least one exact-match finding, got %+v", fr.Findings)
	}
}

func TestInfectedPostcssConfigIsModerateViaSingleHeuristic(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/infected/postcss.config.mjs")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if fr.Severity != Moderate {
		t.Fatalf("expected MODERATE, got %s (findings: %+v)", fr.Severity, fr.Findings)
	}
	for _, f := range fr.Findings {
		if f.Kind == "exact" {
			t.Fatalf("expected no exact matches, got %+v", f)
		}
	}
	if len(fr.Findings) != 1 {
		t.Fatalf("expected exactly 1 heuristic finding, got %d: %+v", len(fr.Findings), fr.Findings)
	}
}

func TestInfectedPostcssObfuscatedCampaignIsHigh(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/infected/postcss.config.obfuscated.mjs")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if fr.Severity != High {
		t.Fatalf("expected HIGH, got %s (findings: %+v)", fr.Severity, fr.Findings)
	}
	foundCampaign := false
	for _, f := range fr.Findings {
		if f.SignatureID == "campaign-id-a8-5741" || f.SignatureID == "campaign-id-a8-regex" {
			foundCampaign = true
		}
	}
	if !foundCampaign {
		t.Fatalf("expected campaign ID signature match, got %+v", fr.Findings)
	}
}

func TestInfectedTailwindConfigIsHighViaTwoHeuristics(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/infected/tailwind.config.js")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if fr.Severity != High {
		t.Fatalf("expected HIGH, got %s (findings: %+v)", fr.Severity, fr.Findings)
	}
	for _, f := range fr.Findings {
		if f.Kind == "exact" {
			t.Fatalf("expected only heuristic matches (no exact IOC), got %+v", f)
		}
	}
	if len(fr.Findings) < 2 {
		t.Fatalf("expected 2+ heuristic findings, got %d: %+v", len(fr.Findings), fr.Findings)
	}
}

func TestInfectedGitignoreWormMarkerIsHigh(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/infected/.gitignore")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if fr.Severity != High {
		t.Fatalf("expected HIGH, got %s (findings: %+v)", fr.Severity, fr.Findings)
	}
}

func TestScanDirAggregatesWorstSeverity(t *testing.T) {
	e := newTestEngine(t)
	res, err := e.ScanDir("testdata/infected")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if res.Severity != High {
		t.Fatalf("expected overall HIGH, got %s", res.Severity)
	}
	if len(res.Files) != 4 {
		t.Fatalf("expected 4 files with findings, got %d: %+v", len(res.Files), res.Files)
	}
}

func TestTargetPathspecsMatchesTargetGlobs(t *testing.T) {
	specs := TargetPathspecs()
	if len(specs) != len(targetGlobs) {
		t.Fatalf("TargetPathspecs() len = %d, want %d", len(specs), len(targetGlobs))
	}
}

func TestIsTargetFile(t *testing.T) {
	cases := map[string]bool{
		"eslint.config.mjs":      true,
		"a/b/tailwind.config.js": true,
		".eslintrc":              true,
		".eslintrc.json":         true,
		".gitignore":             true,
		"package.json":           false,
		"webpack.config.js":      false,
		"README.md":              false,
	}
	for path, want := range cases {
		if got := IsTargetFile(path); got != want {
			t.Errorf("IsTargetFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestLongLineHeuristicIgnoresGitignore(t *testing.T) {
	e := newTestEngine(t)
	longLine := make([]byte, 3000)
	for i := range longLine {
		longLine[i] = 'a'
	}
	findings := e.ScanBytes(".gitignore", longLine)
	for _, f := range findings {
		if f.SignatureID == "heuristic-long-line" {
			t.Fatalf(".gitignore should not trigger the long-line heuristic, got %+v", f)
		}
	}
}
