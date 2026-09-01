// Package dashboard implements gitshield's optional shipping of its local
// audit.log to a gitshield-dashboard instance: POST /v1/ingest, batched,
// with progress tracked so repeated invocations only send new lines. See
// https://github.com/mirzasaikatahmmed/gitshield-dashboard's
// ARCHITECTURE.md §4 for the ingestion contract this implements.
package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

const keyFile = "dashboard-key"

// KeyPath returns the path to gitshield's per-machine dashboard ingestion
// key within dir (gitshield's state directory, typically ~/.gitshield).
func KeyPath(dir string) string {
	return filepath.Join(dir, keyFile)
}

// LoadOrCreateKey returns gitshield's dashboard ingestion key, generating
// and persisting a new random one on first use. This key IS the machine
// identity from the dashboard's point of view: the first successful
// ingest call bearing a given key auto-registers a machine there — there
// is no separate registration step and nothing for a human to configure
// beyond dashboard_url itself.
func LoadOrCreateKey(dir string) (string, error) {
	path := KeyPath(dir)
	if data, err := os.ReadFile(path); err == nil {
		if key := strings.TrimSpace(string(data)); key != "" {
			return key, nil
		}
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		return "", err
	}
	return key, nil
}
