package scanner

import (
	"bytes"
	"regexp"

	"github.com/mirzasaikatahmmed/gitshield/internal/signatures"
)

// This file holds the heuristics for the 2026 VS Code / fake-font variants of
// the campaign: the loader is shipped as a "font" (fa-solid-400.woff2,
// fa-solid-900.woff2, fa-solid-300.llf, fa-solid-600.eot, often in nested
// public/fonts folders), .vscode/tasks.json runs it with node when the folder
// is opened, and payloads are hidden after a long whitespace run in configs
// and ordinary JS files.

// fakeFontFinding flags a font file that is really JavaScript. Real fonts are
// binary with a known magic number; the loader is plain text.
func fakeFontFinding(path string, content []byte, sig signatures.Signature) []Finding {
	if !IsFontFile(path) || len(content) == 0 || isRealFont(content) || !isMostlyText(content) {
		return nil
	}
	head := content
	if len(head) > 200000 {
		head = head[:200000]
	}
	if !jsLikeRe.Match(head) {
		return nil
	}
	return []Finding{{
		File:        path,
		Line:        1,
		SignatureID: sig.ID,
		Kind:        kindLabel(sig),
		Description: sig.Description,
		Excerpt:     excerpt(bytes.TrimSpace(firstLine(content))),
	}}
}

var jsLikeRe = regexp.MustCompile(`global\[|global\.[A-Za-z_]+\s*=|_0x[0-9a-f]{4}|\brequire\(|\bfunction\b`)

func isRealFont(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch string(b[:4]) {
	case "wOF2", "wOFF", "OTTO", "true", "ttcf", "\x00\x01\x00\x00":
		return true
	}
	// Embedded OpenType (.eot): magic number 0x504C at offset 34.
	return len(b) > 36 && b[34] == 0x4C && b[35] == 0x50
}

// isMostlyText reports whether at least 95% of the first 4 KB are printable
// ASCII or whitespace.
func isMostlyText(b []byte) bool {
	n := len(b)
	if n > 4096 {
		n = 4096
	}
	if n == 0 {
		return false
	}
	text := 0
	for _, c := range b[:n] {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 32 && c < 127) {
			text++
		}
	}
	return text*100 >= n*95
}

func firstLine(b []byte) []byte {
	b = bytes.TrimLeft(b, " \t\r\n")
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

var (
	folderOpenRe = regexp.MustCompile(`"runOn"\s*:\s*"folderOpen"`)
	taskLoaderRe = regexp.MustCompile(`node\s+\S*\.(?:woff2?|llf|eot|ttf|otf)\b|node\s+\S*fonts/|\b(?:curl|wget)\b[^"]*\|\s*(?:sh|bash|zsh|cmd)\b|vercel\.app`)
)

// vscodeAutorunFinding flags a .vscode/tasks.json that downloads or runs code
// as soon as the folder is opened — the infection trigger for this variant.
func vscodeAutorunFinding(path string, lines [][]byte, sig signatures.Signature) []Finding {
	if !IsVSCodeTasks(path) {
		return nil
	}
	runOn, loader := -1, -1
	for i, line := range lines {
		if runOn == -1 && folderOpenRe.Match(line) {
			runOn = i
		}
		if loader == -1 && taskLoaderRe.Match(line) {
			loader = i
		}
	}
	if runOn == -1 || loader == -1 {
		return nil
	}
	return []Finding{{
		File:        path,
		Line:        loader + 1,
		SignatureID: sig.ID,
		Kind:        kindLabel(sig),
		Description: sig.Description,
		Excerpt:     excerpt(bytes.TrimSpace(lines[loader])),
	}}
}

var autoTasksOnRe = regexp.MustCompile(`"task\.allowAutomaticTasks"\s*:\s*(?:"on"|true)`)

// vscodeAutoTasksFinding flags a committed .vscode/settings.json that turns on
// automatic tasks, which lets a folder-open task run without a prompt.
func vscodeAutoTasksFinding(path string, lines [][]byte, sig signatures.Signature) []Finding {
	if !IsVSCodeSettings(path) {
		return nil
	}
	for i, line := range lines {
		if autoTasksOnRe.Match(line) {
			return []Finding{{
				File:        path,
				Line:        i + 1,
				SignatureID: sig.ID,
				Kind:        kindLabel(sig),
				Description: sig.Description,
				Excerpt:     excerpt(bytes.TrimSpace(line)),
			}}
		}
	}
	return nil
}

var (
	// A non-space character, then 20+ spaces/tabs, then more code on the same line.
	hiddenRunRe = regexp.MustCompile(`\S[ \t]{20,}\S`)
	// Code shapes the payload starts with, checked just after the whitespace run.
	hiddenCodeRe = regexp.MustCompile(`global\[|global\.[A-Za-z_]+\s*=|_0x[0-9a-f]{4}|\beval\(|\bFunction\(`)
	// Campaign markers: unambiguous on their own.
	campaignMarkerRe = regexp.MustCompile(`global\.i\s*=\s*['"][A-Z]?\d+-\d+(?:-\d+)?['"]|global\[['"]!['"]\]\s*=|global\[['"]_t_[a-z0-9]['"]\]\s*=|_0x4925`)
)

// hiddenWhitespaceFindings flags code pushed out of view by a long run of
// spaces/tabs on the same line. In config files the shape alone is enough
// for a heuristic hit. In other JS files (--deep) minified bundles can share
// the shape, so a campaign marker is required, and then it is reported as an
// exact match.
func hiddenWhitespaceFindings(path string, lines [][]byte, sig signatures.Signature, deep bool) []Finding {
	config := isHeuristicConfigTarget(path, deep)
	nested := deep && IsDeepScriptFile(path) && !config
	if !config && !nested {
		return nil
	}
	var out []Finding
	for i, line := range lines {
		loc := hiddenRunRe.FindIndex(line)
		if loc == nil {
			continue
		}
		tail := line[loc[1]-1:]
		window := tail
		if len(window) > 160 {
			window = window[:160]
		}
		if !hiddenCodeRe.Match(window) {
			continue
		}
		marker := campaignMarkerRe.Match(tail)
		if nested && !marker {
			continue
		}
		kind := kindLabel(sig)
		if marker {
			kind = "exact"
		}
		out = append(out, Finding{
			File:        path,
			Line:        i + 1,
			SignatureID: sig.ID,
			Kind:        kind,
			Description: sig.Description,
			Excerpt:     excerpt(bytes.TrimSpace(tail)),
		})
	}
	return out
}
