package autoupdate

import (
	"os"
	"testing"
	"time"
)

const testCheckName = "test-check"

func TestIsDueOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	if !IsDue(dir, testCheckName, 24*time.Hour) {
		t.Fatalf("expected IsDue to be true when no state file exists yet")
	}
}

func TestRecordNowThenNotDue(t *testing.T) {
	dir := t.TempDir()
	if err := RecordNow(dir, testCheckName); err != nil {
		t.Fatalf("RecordNow: %v", err)
	}
	if IsDue(dir, testCheckName, 24*time.Hour) {
		t.Fatalf("expected IsDue to be false immediately after RecordNow")
	}
}

func TestIsDueAfterIntervalElapses(t *testing.T) {
	dir := t.TempDir()
	if err := RecordNow(dir, testCheckName); err != nil {
		t.Fatalf("RecordNow: %v", err)
	}
	if !IsDue(dir, testCheckName, 0) {
		t.Fatalf("expected IsDue to be true once the interval (0) has elapsed")
	}
}

func TestIsDueOnCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(StatePath(dir, testCheckName), []byte("not-a-timestamp"), 0o600); err != nil {
		t.Fatalf("writing corrupt state file: %v", err)
	}
	if !IsDue(dir, testCheckName, 24*time.Hour) {
		t.Fatalf("expected IsDue to be true for an unparseable state file")
	}
}

func TestChecksAreIndependent(t *testing.T) {
	dir := t.TempDir()
	if err := RecordNow(dir, "check-a"); err != nil {
		t.Fatalf("RecordNow: %v", err)
	}
	if !IsDue(dir, "check-b", 24*time.Hour) {
		t.Fatalf("expected check-b to still be due after only check-a was recorded")
	}
}
