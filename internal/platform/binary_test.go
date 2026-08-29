package platform

import "testing"

func TestReleaseNames(t *testing.T) {
	if got := ReleaseBinaryName("linux", "amd64"); got != "gitshield-linux-amd64" {
		t.Fatalf("linux binary name = %q", got)
	}
	if got := ReleaseBinaryName("windows", "amd64"); got != "gitshield-windows-amd64.exe" {
		t.Fatalf("windows binary name = %q", got)
	}
	if got := ReleaseArchiveName("windows", "arm64"); got != "gitshield-windows-arm64.zip" {
		t.Fatalf("windows archive name = %q", got)
	}
	if got := ReleaseArchiveName("darwin", "arm64"); got != "gitshield-darwin-arm64.tar.gz" {
		t.Fatalf("darwin archive name = %q", got)
	}
}
