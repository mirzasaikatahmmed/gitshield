// Package autoupdate implements the rate-limiting for gitshield's
// background best-effort checks (binary/signature auto-update, dashboard
// log shipping): at most once per interval, tracked via a named timestamp
// file in ~/.gitshield/. Each check gets its own name/interval so they run
// independently of each other. The actual network work lives in
// cmd/gitshield, which only calls in here to decide whether it's due and
// to record that it ran.
package autoupdate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// StatePath returns the timestamp file path for the named check within dir
// (gitshield's state directory, typically ~/.gitshield).
func StatePath(dir, name string) string {
	return filepath.Join(dir, name)
}

// IsDue reports whether at least interval has passed since the last
// recorded run of the named check in dir. A missing or
// unreadable/unparseable timestamp file counts as due (first run, or a
// corrupted state file shouldn't wedge the check off forever).
func IsDue(dir, name string, interval time.Duration) bool {
	data, err := os.ReadFile(StatePath(dir, name))
	if err != nil {
		return true
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return true
	}
	last := time.Unix(sec, 0)
	return time.Since(last) >= interval
}

// RecordNow writes the current time to the named check's timestamp file,
// marking it as having just run (regardless of outcome) so IsDue won't
// fire again until the next interval elapses.
func RecordNow(dir, name string) error {
	return os.WriteFile(StatePath(dir, name), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600)
}
