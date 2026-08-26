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
	".eslintrc",
	".eslintrc.js",
	".eslintrc.cjs",
	".eslintrc.json",
	".eslintrc.yaml",
	".eslintrc.yml",
	".gitignore",
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

// IsConfigFile reports whether path is one of the executable config file
// classes (i.e. a target file that is NOT .gitignore) — the payload-bearing
// heuristics (long-line, spawn+eval, eth-address) only make sense here.
func IsConfigFile(path string) bool {
	return IsTargetFile(path) && !IsGitignore(path)
}
