// Package audit implements gitshield's append-only local audit trail at
// ~/.gitshield/audit.log, one JSON object per line, recording every scan
// result and especially every --force-unsafe override.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Entry is one audit log record.
type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"` // "clone", "pull", "scan"
	RepoRef    string    `json:"repo_ref,omitempty"`
	User       string    `json:"user"`
	Severity   string    `json:"severity"`
	Signatures []string  `json:"matched_signatures"`
	Overridden bool      `json:"overridden"`
	Proceeded  bool      `json:"proceeded"`
}

// DefaultPath returns ~/.gitshield/audit.log.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".gitshield", "audit.log"), nil
}

// Append writes entry as a single JSON line to path, creating the parent
// directory and file if needed. Opens O_APPEND so concurrent gitshield
// invocations never truncate or interleave-corrupt each other's writes
// (each Write of a single line is append-only at the OS level).
func Append(path string, entry Entry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	_, err = f.Write(line)
	return err
}

// CurrentUser returns the best-effort local username for audit attribution.
func CurrentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}
