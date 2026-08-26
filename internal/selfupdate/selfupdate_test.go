package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.0", "0.1.0", true},
		{"v0.1.0", "0.1.0", false},
		{"v0.1.1", "0.1.0", true},
		{"v0.0.9", "0.1.0", false},
		{"v1.0.0", "0.9.9", true},
		{"v0.1.0-rc1", "0.1.0", false},
	}
	for _, c := range cases {
		if got := IsNewer(c.latest, c.current); got != c.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestFindAssets(t *testing.T) {
	rel := Release{
		TagName: "v0.2.0",
		Assets: []Asset{
			{Name: "gitshield-linux-amd64.tar.gz", URL: "https://example/linux-amd64.tar.gz"},
			{Name: "gitshield-linux-amd64.tar.gz.sha256", URL: "https://example/linux-amd64.tar.gz.sha256"},
			{Name: "gitshield-darwin-arm64.tar.gz", URL: "https://example/darwin-arm64.tar.gz"},
		},
	}

	tb, sum, err := FindAssets(rel, "linux", "amd64")
	if err != nil {
		t.Fatalf("FindAssets: %v", err)
	}
	if tb.URL != "https://example/linux-amd64.tar.gz" || sum.URL != "https://example/linux-amd64.tar.gz.sha256" {
		t.Fatalf("unexpected assets: %+v %+v", tb, sum)
	}

	if _, _, err := FindAssets(rel, "darwin", "arm64"); err == nil {
		t.Fatalf("expected error for missing checksum asset")
	}
	if _, _, err := FindAssets(rel, "windows", "amd64"); err == nil {
		t.Fatalf("expected error for missing platform")
	}
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("hello world")
	sum := sha256.Sum256(data)
	checksumFile := []byte(hex.EncodeToString(sum[:]) + "  gitshield-linux-amd64.tar.gz\n")

	if err := VerifyChecksum(data, checksumFile, "gitshield-linux-amd64.tar.gz"); err != nil {
		t.Fatalf("expected valid checksum to verify, got: %v", err)
	}

	tampered := []byte("hello world!")
	if err := VerifyChecksum(tampered, checksumFile, "gitshield-linux-amd64.tar.gz"); err == nil {
		t.Fatalf("expected tampered data to fail checksum verification")
	}

	if err := VerifyChecksum(data, checksumFile, "some-other-file.tar.gz"); err == nil {
		t.Fatalf("expected missing entry to error")
	}
}

func TestExtractFile(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	content := []byte("fake binary contents")
	if err := tw.WriteHeader(&tar.Header{Name: "gitshield-linux-amd64", Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatalf("writing tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("writing tar content: %v", err)
	}
	tw.Close()
	gz.Close()

	got, err := ExtractFile(buf.Bytes(), "gitshield-linux-amd64")
	if err != nil {
		t.Fatalf("ExtractFile: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("ExtractFile content mismatch: got %q, want %q", got, content)
	}

	if _, err := ExtractFile(buf.Bytes(), "does-not-exist"); err == nil {
		t.Fatalf("expected error for missing entry")
	}
}
