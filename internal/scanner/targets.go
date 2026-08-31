package scanner

import (
	"path/filepath"
)

// targetGlobs are matched against the base filename only (not the full
// relative path), so eslint.config.mjs is caught regardless of which
// subdirectory it lives in.
var targetGlobs = []string{
	"eslint.config.js",
	"eslint.config.mjs",
	"eslint.config.cjs",
	"eslint.config.ts",
	"postcss.config.js",
	"postcss.config.mjs",
	"postcss.config.cjs",
	"postcss.config.ts",
	"prettier.config.js",
	"prettier.config.mjs",
	"prettier.config.cjs",
	"prettier.config.ts",
	"tailwind.config.js",
	"tailwind.config.mjs",
	"tailwind.config.cjs",
	"tailwind.config.ts",
	"next.config.js",
	"next.config.mjs",
	"next.config.ts",
	"babel.config.js",
	"jest.config.js",
	"jest.config.mjs",
	"jest.config.ts",
	"config.bat",
	"temp_auto_push.bat",
	"temp_interactive_push.bat",
	".eslintrc",
	".eslintrc.js",
	".eslintrc.cjs",
	".eslintrc.json",
	".eslintrc.yaml",
	".eslintrc.yml",
	".gitignore",
	"package.json",
}

// deepScanExts are the extensions considered by --deep for arbitrary
// top-level JS files that aren't one of the known target filenames above.
var deepScanExts = []string{".js", ".mjs", ".cjs"}

// IsDeepTargetFile reports whether path is a top-level (not nested in a
// subdirectory) *.js/*.mjs/*.cjs file eligible for the --deep heuristic
// scan. Restricted to top-level only: the campaign's payload lands in
// files a build tool loads directly from the repo root, and recursing into
// every JS file in the tree (node_modules included) would be slow and
// noisy for a low marginal detection benefit.
func IsDeepTargetFile(path string) bool {
	if filepath.Dir(path) != "." {
		return false
	}
	ext := filepath.Ext(path)
	for _, e := range deepScanExts {
		if ext == e {
			return true
		}
	}
	return false
}

// IsScanTarget reports whether path should be scanned: always true for the
// fixed target filenames, and additionally true for top-level *.js/*.mjs/*.cjs
// files when deep is enabled (the --deep flag).
func IsScanTarget(path string, deep bool) bool {
	return IsTargetFile(path) || (deep && IsDeepTargetFile(path))
}

// TargetPathspecs returns the base filenames gitshield scans, for use as
// git log pathspecs when walking history.
func TargetPathspecs() []string {
	out := make([]string, len(targetGlobs))
	copy(out, targetGlobs)
	return out
}

// IsTargetFile reports whether path (or its base name) is one gitshield
// scans: the known config-file classes from the campaign, plus .gitignore
// (scanned only for the worm self-exclusion marker, not general heuristics).
func IsTargetFile(path string) bool {
	base := filepath.Base(path)
	for _, g := range targetGlobs {
		if base == g {
			return true
		}
	}
	return false
}

// IsGitignore reports whether path is a .gitignore file, used to scope the
// worm-marker heuristic to that file only.
func IsGitignore(path string) bool {
	return filepath.Base(path) == ".gitignore"
}

// wormArtifacts are batch files scanned only for exact worm IOC matches, not
// config-file heuristics like long-line or eth-address.
var wormArtifacts = []string{
	"config.bat",
	"temp_auto_push.bat",
	"temp_interactive_push.bat",
}

func IsWormArtifact(path string) bool {
	base := filepath.Base(path)
	for _, w := range wormArtifacts {
		if base == w {
			return true
		}
	}
	return false
}

// wormArtifactFinding returns a HIGH-severity finding when a known worm
// propagation batch file is present on disk (presence alone is the IOC).
func wormArtifactFinding(path string) *Finding {
	switch filepath.Base(path) {
	case "config.bat":
		return &Finding{
			File: path, Line: 1, SignatureID: "worm-batch-config-bat", Kind: "exact",
			Description: "PolinRider hidden orchestrator batch file (config.bat)",
			Excerpt:     "config.bat",
		}
	case "temp_auto_push.bat":
		return &Finding{
			File: path, Line: 1, SignatureID: "worm-batch-auto-push", Kind: "exact",
			Description: "Worm propagation artifact (temp_auto_push.bat)",
			Excerpt:     "temp_auto_push.bat",
		}
	case "temp_interactive_push.bat":
		return &Finding{
			File: path, Line: 1, SignatureID: "worm-batch-interactive-push", Kind: "exact",
			Description: "Worm propagation artifact (temp_interactive_push.bat)",
			Excerpt:     "temp_interactive_push.bat",
		}
	default:
		return nil
	}
}

// IsPackageJSON reports whether path is a package.json file, used to scope
// the npm-postinstall-worm heuristics to that file only.
func IsPackageJSON(path string) bool {
	return filepath.Base(path) == "package.json"
}

// IsConfigFile reports whether path is one of the executable config file
// classes (i.e. a target file that is NOT .gitignore, a worm batch file, or
// package.json) — the payload-bearing heuristics (long-line, spawn+eval,
// eth-address) only make sense here; package.json gets its own
// postinstall-specific heuristics instead.
func IsConfigFile(path string) bool {
	return IsTargetFile(path) && !IsGitignore(path) && !IsWormArtifact(path) && !IsPackageJSON(path)
}
