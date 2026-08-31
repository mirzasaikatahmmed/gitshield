package scanner

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/mirzasaikatahmmed/gitshield/internal/signatures"
)

const excerptMaxLen = 160

func excerpt(line []byte) string {
	s := string(line)
	if len(s) > excerptMaxLen {
		return s[:excerptMaxLen] + "…"
	}
	return s
}

func kindLabel(sig signatures.Signature) string {
	if sig.Exact {
		return "exact"
	}
	return "heuristic"
}

func matchString(path string, lines [][]byte, sig signatures.Signature) []Finding {
	var out []Finding
	pat := []byte(sig.Pattern)
	for i, line := range lines {
		if bytes.Contains(line, pat) {
			out = append(out, Finding{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: sig.Description,
				Excerpt:     excerpt(line),
			})
		}
	}
	return out
}

func matchRegex(path string, lines [][]byte, sig signatures.Signature) []Finding {
	re, err := regexp.Compile(sig.Pattern)
	if err != nil {
		return nil
	}
	var out []Finding
	for i, line := range lines {
		if re.Match(line) {
			out = append(out, Finding{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: sig.Description,
				Excerpt:     excerpt(line),
			})
		}
	}
	return out
}

func runHeuristic(path string, lines [][]byte, text string, sig signatures.Signature, deep bool) []Finding {
	switch sig.HeuristicName {
	case signatures.HeuristicLongLine:
		return heuristicLongLine(path, lines, sig, deep)
	case signatures.HeuristicSpawnEval:
		return heuristicSpawnEval(path, lines, sig, deep)
	case signatures.HeuristicEthAddress:
		return heuristicEthAddress(path, lines, sig, deep)
	case signatures.HeuristicGitignoreWorm:
		return heuristicGitignoreWorm(path, lines, sig)
	case signatures.HeuristicPostinstallCurlPipeShell:
		return heuristicPostinstallCurlPipeShell(path, lines, sig)
	case signatures.HeuristicPostinstallPowershellCradle:
		return heuristicPostinstallPowershellCradle(path, lines, sig)
	case signatures.HeuristicPostinstallBase64Shell:
		return heuristicPostinstallBase64Shell(path, lines, sig)
	default:
		return nil
	}
}

// isHeuristicConfigTarget reports whether path is eligible for the
// config-file-scoped heuristics (long-line, spawn+eval, eth-address): the
// fixed config-file classes always, plus top-level *.js/*.mjs/*.cjs files
// when --deep is enabled.
func isHeuristicConfigTarget(path string, deep bool) bool {
	return IsConfigFile(path) || (deep && IsDeepTargetFile(path))
}

const longLineThreshold = 2000

// heuristicLongLine flags any line exceeding ~2000 chars in a target config
// file — a strong signal of a packed/obfuscated payload appended after a
// normal, short config export. Does not apply to .gitignore.
func heuristicLongLine(path string, lines [][]byte, sig signatures.Signature, deep bool) []Finding {
	if !isHeuristicConfigTarget(path, deep) {
		return nil
	}
	var out []Finding
	for i, line := range lines {
		if len(line) > longLineThreshold {
			out = append(out, Finding{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: fmt.Sprintf("%s (line length %d)", sig.Description, len(line)),
				Excerpt:     excerpt(line),
			})
		}
	}
	return out
}

var spawnRe = regexp.MustCompile(`child_process|\bspawn\s*\(`)
var detachedRe = regexp.MustCompile(`detached\s*:\s*true`)
var evalOrDynamicImportRe = regexp.MustCompile(`\beval\s*\(|\brequire\s*\(\s*['"\x60]https?://|import\s*\(\s*['"\x60]https?://`)

// heuristicSpawnEval flags a child_process spawn with detached:true combined
// with eval or a dynamic require/import of remote (http/https) content —
// the shape of the campaign's second-stage loader. Requires both signals to
// appear somewhere in the file (not necessarily the same line) since minified
// payloads often split these across a single very long line already caught
// by heuristicLongLine, or across a small handful of short lines.
func heuristicSpawnEval(path string, lines [][]byte, sig signatures.Signature, deep bool) []Finding {
	if !isHeuristicConfigTarget(path, deep) {
		return nil
	}
	hasSpawnDetached := false
	hasEvalOrRemote := false
	spawnLine := -1
	for i, line := range lines {
		if spawnRe.Match(line) && detachedRe.Match(line) {
			hasSpawnDetached = true
			if spawnLine == -1 {
				spawnLine = i
			}
		}
		if evalOrDynamicImportRe.Match(line) {
			hasEvalOrRemote = true
			if spawnLine == -1 {
				spawnLine = i
			}
		}
	}
	if hasSpawnDetached && hasEvalOrRemote {
		return []Finding{{
			File:        path,
			Line:        spawnLine + 1,
			SignatureID: sig.ID,
			Kind:        kindLabel(sig),
			Description: sig.Description,
			Excerpt:     excerpt(lines[spawnLine]),
		}}
	}
	return nil
}

var ethAddressRe = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)

// heuristicEthAddress flags Ethereum-address-like strings in a config file,
// which has no legitimate reason to reference one.
func heuristicEthAddress(path string, lines [][]byte, sig signatures.Signature, deep bool) []Finding {
	if !isHeuristicConfigTarget(path, deep) {
		return nil
	}
	var out []Finding
	for i, line := range lines {
		if loc := ethAddressRe.FindIndex(line); loc != nil {
			out = append(out, Finding{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: sig.Description,
				Excerpt:     excerpt(line),
			})
		}
	}
	return out
}

// npmAutoRunHookRe matches the package.json "scripts" keys npm executes on
// its own during `npm install` — the auto-run lifecycle hooks that make
// package.json a worm vector. Ordinary scripts (test/build/start/...)
// require an explicit `npm run` and are deliberately excluded.
var npmAutoRunHookRe = regexp.MustCompile(`"(?:preinstall|install|postinstall|prepare)"\s*:`)

var curlWgetPipeShellRe = regexp.MustCompile(`\b(?:curl|wget)\b[^"]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash)\b`)

// heuristicPostinstallCurlPipeShell flags an npm auto-run lifecycle script
// that pipes a curl/wget download straight into a shell interpreter — the
// classic self-propagating "curl | bash" worm pattern. See default.yaml for
// the false-positive rationale.
func heuristicPostinstallCurlPipeShell(path string, lines [][]byte, sig signatures.Signature) []Finding {
	if !IsPackageJSON(path) {
		return nil
	}
	var out []Finding
	for i, line := range lines {
		if npmAutoRunHookRe.Match(line) && curlWgetPipeShellRe.Match(line) {
			out = append(out, Finding{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: sig.Description,
				Excerpt:     excerpt(line),
			})
		}
	}
	return out
}

var powershellDownloadCradleRe = regexp.MustCompile(`(?i)\b(?:iwr|invoke-webrequest|irm|invoke-restmethod)\b[^"]*\|\s*(?:iex|invoke-expression)\b`)

// heuristicPostinstallPowershellCradle flags an npm auto-run lifecycle
// script containing a PowerShell download-cradle (iwr/irm piped into iex) —
// the Windows-targeting worm variant. See default.yaml for the
// false-positive rationale.
func heuristicPostinstallPowershellCradle(path string, lines [][]byte, sig signatures.Signature) []Finding {
	if !IsPackageJSON(path) {
		return nil
	}
	var out []Finding
	for i, line := range lines {
		if npmAutoRunHookRe.Match(line) && powershellDownloadCradleRe.Match(line) {
			out = append(out, Finding{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: sig.Description,
				Excerpt:     excerpt(line),
			})
		}
	}
	return out
}

var base64PipeShellRe = regexp.MustCompile(`\bbase64\s+(?:-d|--decode)\b[^"]*\|\s*(?:sh|bash|zsh|dash)\b`)

// heuristicPostinstallBase64Shell flags an npm auto-run lifecycle script
// that decodes a base64 blob and pipes it straight into a shell interpreter
// — an obfuscation technique to dodge keyword/URL scanning of the script
// text. See default.yaml for the false-positive rationale.
func heuristicPostinstallBase64Shell(path string, lines [][]byte, sig signatures.Signature) []Finding {
	if !IsPackageJSON(path) {
		return nil
	}
	var out []Finding
	for i, line := range lines {
		if npmAutoRunHookRe.Match(line) && base64PipeShellRe.Match(line) {
			out = append(out, Finding{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: sig.Description,
				Excerpt:     excerpt(line),
			})
		}
	}
	return out
}

// heuristicGitignoreWorm flags a .gitignore that references the worm's
// self-exclusion batch files. This is scoped to .gitignore only.
func heuristicGitignoreWorm(path string, lines [][]byte, sig signatures.Signature) []Finding {
	if !IsGitignore(path) {
		return nil
	}
	var out []Finding
	for i, line := range lines {
		if bytes.Contains(line, []byte("temp_auto_push.bat")) ||
			bytes.Contains(line, []byte("temp_interactive_push.bat")) ||
			bytes.Contains(line, []byte("config.bat")) {
			out = append(out, Finding{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: sig.Description,
				Excerpt:     excerpt(line),
			})
		}
	}
	return out
}
