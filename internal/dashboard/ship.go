package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mirzasaikatahmmed/gitshield/internal/audit"
)

const cursorFile = "dashboard-ship-cursor"

// maxBatchSize caps how many audit.log lines go into a single POST /v1/ingest
// request — defensive against a very large unshipped backlog (e.g. shipping
// was misconfigured for a while and audit.log grew in the meantime).
const maxBatchSize = 200

const requestTimeout = 15 * time.Second

// CursorPath returns the path to the ship-progress cursor file within dir.
func CursorPath(dir string) string {
	return filepath.Join(dir, cursorFile)
}

func loadCursor(dir string) int {
	data, err := os.ReadFile(CursorPath(dir))
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func saveCursor(dir string, n int) error {
	return os.WriteFile(CursorPath(dir), []byte(strconv.Itoa(n)), 0o600)
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// Ship reads auditLogPath (gitshield's audit.log — one JSON audit.Entry per
// line) and POSTs any lines not yet shipped to dashboardURL's ingestion
// API, in batches of up to maxBatchSize, tracking progress via a cursor
// file in stateDir so repeated calls only send new lines. A line that
// fails to parse as JSON is skipped (and still counted as consumed —
// retrying a permanently-malformed line forever would accomplish
// nothing). Best-effort: a request failure stops shipping for this call
// without erroring, leaving the cursor where it was so the same lines are
// retried next time. Returns the number of lines consumed (shipped or
// skipped), purely for an optional diagnostic message.
func Ship(stateDir, auditLogPath, dashboardURL string) int {
	if dashboardURL == "" {
		return 0
	}
	lines, err := readLines(auditLogPath)
	if err != nil {
		return 0
	}
	cursor := loadCursor(stateDir)
	if cursor > len(lines) {
		cursor = 0 // audit.log was rotated/truncated since the last run
	}
	if cursor >= len(lines) {
		return 0
	}
	key, err := LoadOrCreateKey(stateDir)
	if err != nil {
		return 0
	}
	hostname, _ := os.Hostname()

	consumed := 0
	for cursor < len(lines) {
		end := cursor + maxBatchSize
		if end > len(lines) {
			end = len(lines)
		}
		batch := lines[cursor:end]

		var entries []audit.Entry
		for _, line := range batch {
			var e audit.Entry
			if err := json.Unmarshal([]byte(line), &e); err == nil {
				entries = append(entries, e)
			}
		}

		if len(entries) > 0 {
			if err := postBatch(dashboardURL, key, hostname, entries); err != nil {
				break // leave cursor at `cursor`; retry this batch next time
			}
		}

		cursor = end
		consumed += len(batch)
		if err := saveCursor(stateDir, cursor); err != nil {
			break
		}
	}
	return consumed
}

type ingestRequest struct {
	Events []audit.Entry `json:"events"`
}

func postBatch(dashboardURL, key, hostname string, entries []audit.Entry) error {
	body, err := json.Marshal(ingestRequest{Events: entries})
	if err != nil {
		return err
	}

	url := strings.TrimRight(dashboardURL, "/") + "/v1/ingest"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	if hostname != "" {
		req.Header.Set("X-Gitshield-Machine", hostname)
	}

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("dashboard ingest returned status %d", resp.StatusCode)
	}
	return nil
}
