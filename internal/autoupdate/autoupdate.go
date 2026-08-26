// Package autoupdate implements the rate-limiting for gitshield's
// background auto-update check: at most once per interval (default 24h),
// tracked via a timestamp file in ~/.gitshield/. The actual network work
// (fetching signatures/releases) lives in cmd/gitshield, which only calls
// in here to decide whether it's due and to record that it ran.
package autoupdate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// stateFile is the name of the last-check timestamp file within the
// gitshield state directory (e.g. ~/.gitshield).
const stateFile = "last-auto-update-check"

// StatePath returns the timestamp file path within dir (gitshield's state
// directory, typically ~/.gitshield).
func StatePath(dir string) string {
	return filepath.Join(dir, stateFile)
}

// IsDue reports whether at least interval has passed since the last
// recorded check in dir. A missing or unreadable/unparseable timestamp
// file counts as due (first run, or a corrupted state file shouldn't wedge
// auto-update off forever).
func IsDue(dir string, interval time.Duration) bool {
	data, err := os.ReadFile(StatePath(dir))
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

// RecordNow writes the current time to dir's timestamp file, marking a
// check as having just run (regardless of whether it found or applied any
// update) so IsDue won't fire again until the next interval elapses.
func RecordNow(dir string) error {
	return os.WriteFile(StatePath(dir), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600)
}
