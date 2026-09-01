package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirzasaikatahmmed/gitshield/internal/audit"
)

func TestLoadOrCreateKeyPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	key1, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if key1 == "" {
		t.Fatalf("expected a non-empty generated key")
	}
	key2, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey (second call): %v", err)
	}
	if key1 != key2 {
		t.Fatalf("expected the same key to be reused, got %q then %q", key1, key2)
	}
}

func writeAuditLog(t *testing.T, dir string, entries []audit.Entry) string {
	t.Helper()
	path := filepath.Join(dir, "audit.log")
	var sb strings.Builder
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshaling test entry: %v", err)
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("writing audit.log: %v", err)
	}
	return path
}

func sampleEntry(action string) audit.Entry {
	return audit.Entry{
		Timestamp:  time.Now().UTC(),
		Action:     action,
		RepoRef:    "https://github.com/org/repo.git",
		User:       "saikat",
		Severity:   "CLEAN",
		Signatures: nil,
		Overridden: false,
		Proceeded:  true,
	}
}

func TestShipNoopsWithoutDashboardURL(t *testing.T) {
	dir := t.TempDir()
	logPath := writeAuditLog(t, dir, []audit.Entry{sampleEntry("clone")})
	if n := Ship(dir, logPath, ""); n != 0 {
		t.Fatalf("expected Ship to no-op with empty dashboardURL, consumed %d", n)
	}
}

func TestShipPostsUnshippedEntriesAndAdvancesCursor(t *testing.T) {
	dir := t.TempDir()
	logPath := writeAuditLog(t, dir, []audit.Entry{sampleEntry("clone"), sampleEntry("pull")})

	var gotAuth, gotMachine string
	var gotBody ingestRequest
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotAuth = r.Header.Get("Authorization")
		gotMachine = r.Header.Get("X-Gitshield-Machine")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"received":2,"ingested":2,"duplicates":0,"rejected":[]}`))
	}))
	defer srv.Close()

	n := Ship(dir, logPath, srv.URL)
	if n != 2 {
		t.Fatalf("expected 2 lines consumed, got %d", n)
	}
	if requests != 1 {
		t.Fatalf("expected exactly 1 request for a small batch, got %d", requests)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") || len(gotAuth) < 10 {
		t.Fatalf("expected a Bearer token, got %q", gotAuth)
	}
	if gotMachine == "" {
		t.Fatalf("expected X-Gitshield-Machine header to be set to the hostname")
	}
	if len(gotBody.Events) != 2 || gotBody.Events[0].Action != "clone" || gotBody.Events[1].Action != "pull" {
		t.Fatalf("unexpected request body: %+v", gotBody)
	}

	// Second call with no new lines should not hit the server again.
	requests = 0
	if n := Ship(dir, logPath, srv.URL); n != 0 {
		t.Fatalf("expected 0 lines consumed on second call, got %d", n)
	}
	if requests != 0 {
		t.Fatalf("expected no request when there's nothing new to ship, got %d", requests)
	}
}

func TestShipOnlySendsNewLinesAfterAppend(t *testing.T) {
	dir := t.TempDir()
	logPath := writeAuditLog(t, dir, []audit.Entry{sampleEntry("clone")})

	var lastBody ingestRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"received":1,"ingested":1,"duplicates":0,"rejected":[]}`))
	}))
	defer srv.Close()

	Ship(dir, logPath, srv.URL)

	// Append a second entry, as a real invocation would after logAudit.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("appending to audit.log: %v", err)
	}
	line, _ := json.Marshal(sampleEntry("add"))
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatalf("writing appended entry: %v", err)
	}
	f.Close()

	n := Ship(dir, logPath, srv.URL)
	if n != 1 {
		t.Fatalf("expected exactly 1 new line consumed, got %d", n)
	}
	if len(lastBody.Events) != 1 || lastBody.Events[0].Action != "add" {
		t.Fatalf("expected only the newly-appended entry to be sent, got %+v", lastBody.Events)
	}
}

func TestShipSkipsMalformedLinesButAdvancesCursor(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(logPath, []byte("not valid json\n"), 0o600); err != nil {
		t.Fatalf("writing audit.log: %v", err)
	}

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	n := Ship(dir, logPath, srv.URL)
	if n != 1 {
		t.Fatalf("expected the malformed line to be consumed, got %d", n)
	}
	if requests != 0 {
		t.Fatalf("expected no HTTP request for an all-malformed batch, got %d", requests)
	}

	// Cursor should now be past the malformed line, so a second call is a no-op.
	if n := Ship(dir, logPath, srv.URL); n != 0 {
		t.Fatalf("expected 0 on second call, got %d", n)
	}
}

func TestShipLeavesCursorInPlaceOnServerError(t *testing.T) {
	dir := t.TempDir()
	logPath := writeAuditLog(t, dir, []audit.Entry{sampleEntry("clone")})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	if n := Ship(dir, logPath, srv.URL); n != 0 {
		t.Fatalf("expected 0 lines consumed on server error, got %d", n)
	}
	if got := loadCursor(dir); got != 0 {
		t.Fatalf("expected cursor to remain at 0 after a failed request, got %d", got)
	}
}
