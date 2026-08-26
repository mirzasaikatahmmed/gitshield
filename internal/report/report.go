// Package report renders scan results as either a human-readable summary
// or JSON (for --json / CI piping), and maps outcomes to gitshield's exit
// code contract.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/mirzasaikatahmmed/gitshield/internal/scanner"
)

// Exit codes per the gitshield CLI contract.
const (
	ExitClean             = 0
	ExitModerateProceeded = 1
	ExitHighBlocked       = 2
	ExitHighOverridden    = 3
)

// JSONReport is the shape emitted by --json.
type JSONReport struct {
	Severity     string               `json:"severity"`
	FilesScanned int                  `json:"files_scanned"`
	Files        []scanner.FileResult `json:"files"`
	Proceeded    bool                 `json:"proceeded"`
	Overridden   bool                 `json:"overridden"`
	ExitCode     int                  `json:"exit_code"`
}

// PrintHuman writes a short human-readable scan report to w.
func PrintHuman(w io.Writer, res scanner.Result, repoRef string) {
	fmt.Fprintf(w, "gitshield scan report\n")
	if repoRef != "" {
		fmt.Fprintf(w, "  target:         %s\n", repoRef)
	}
	fmt.Fprintf(w, "  files scanned:  %d\n", res.FilesScanned)
	fmt.Fprintf(w, "  severity:       %s\n", res.Severity)

	if len(res.Files) == 0 {
		fmt.Fprintf(w, "  no matches found\n")
		return
	}

	fmt.Fprintf(w, "\nfindings:\n")
	for _, fr := range res.Files {
		fmt.Fprintf(w, "  %s  [%s]\n", fr.Path, fr.Severity)
		for _, f := range fr.Findings {
			ref := ""
			if f.Ref != "" {
				ref = fmt.Sprintf(" (commit %s)", shortRef(f.Ref))
			}
			fmt.Fprintf(w, "    line %-6d %-9s %-32s %s%s\n", f.Line, "["+f.Kind+"]", f.SignatureID, f.Description, ref)
			if f.Excerpt != "" {
				fmt.Fprintf(w, "      | %s\n", f.Excerpt)
			}
		}
	}
}

func shortRef(ref string) string {
	if len(ref) > 12 {
		return ref[:12]
	}
	return ref
}

// PrintJSON writes the JSON report to w.
func PrintJSON(w io.Writer, res scanner.Result, proceeded, overridden bool, exitCode int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(JSONReport{
		Severity:     res.Severity.String(),
		FilesScanned: res.FilesScanned,
		Files:        res.Files,
		Proceeded:    proceeded,
		Overridden:   overridden,
		ExitCode:     exitCode,
	})
}

// MatchedSignatureIDs returns the deduplicated, sorted-by-first-seen list of
// signature IDs matched across a scan result, for audit logging.
func MatchedSignatureIDs(res scanner.Result) []string {
	seen := map[string]bool{}
	var ids []string
	for _, fr := range res.Files {
		for _, f := range fr.Findings {
			if !seen[f.SignatureID] {
				seen[f.SignatureID] = true
				ids = append(ids, f.SignatureID)
			}
		}
	}
	return ids
}

// SummaryLine renders a compact one-line severity + signature summary,
// useful for the confirmation prompt and audit log.
func SummaryLine(res scanner.Result) string {
	ids := MatchedSignatureIDs(res)
	return fmt.Sprintf("%s (%d file(s), signatures: %s)", res.Severity, len(res.Files), strings.Join(ids, ", "))
}
