// Package selfupdate implements gitshield's own binary self-update:
// checking the GitHub Releases API for a newer tagged build, downloading
// the release asset matching the running OS/arch, and verifying it against
// the checksum file the release workflow publishes alongside it
// (gitshield-<goos>-<goarch>.tar.gz or .zip + matching .sha256).
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mirzasaikatahmmed/gitshield/internal/platform"
)

// DefaultRepo is the GitHub "owner/repo" gitshield checks by default.
const DefaultRepo = "mirzasaikatahmmed/gitshield"

// Asset is one downloadable file attached to a GitHub release.
type Asset struct {
	Name string
	URL  string
}

// Release is the subset of the GitHub Releases API response gitshield needs.
type Release struct {
	TagName string
	Assets  []Asset
}

// FetchLatest queries the GitHub API for repo's latest published release.
func FetchLatest(repo string) (Release, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "gitshield-cli")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return Release{}, fmt.Errorf("no published releases found for %s", repo)
	}
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("unexpected status %d from GitHub releases API", resp.StatusCode)
	}

	var raw struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Release{}, fmt.Errorf("parsing GitHub API response: %w", err)
	}

	rel := Release{TagName: raw.TagName}
	for _, a := range raw.Assets {
		rel.Assets = append(rel.Assets, Asset{Name: a.Name, URL: a.BrowserDownloadURL})
	}
	return rel, nil
}

// FindAssets locates the release archive and its detached checksum file for
// the given goos/goarch, matching the naming the release workflow publishes.
func FindAssets(rel Release, goos, goarch string) (archive, checksum Asset, err error) {
	wantArchive := platform.ReleaseArchiveName(goos, goarch)
	wantSum := wantArchive + ".sha256"
	for _, a := range rel.Assets {
		switch a.Name {
		case wantArchive:
			archive = a
		case wantSum:
			checksum = a
		}
	}
	if archive.URL == "" {
		return Asset{}, Asset{}, fmt.Errorf("release %s has no asset %q", rel.TagName, wantArchive)
	}
	if checksum.URL == "" {
		return Asset{}, Asset{}, fmt.Errorf("release %s has no checksum asset %q", rel.TagName, wantSum)
	}
	return archive, checksum, nil
}

// Download fetches url and returns its body, capped at maxBytes.
func Download(url string, maxBytes int64) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// VerifyChecksum checks that sha256(data) matches the digest for wantName
// in a `shasum -a 256` style checksum file ("<hex>  <filename>\n").
func VerifyChecksum(data []byte, checksumFile []byte, wantName string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])

	for _, line := range strings.Split(string(checksumFile), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		digest, name := fields[0], strings.TrimPrefix(fields[1], "*")
		if name != wantName {
			continue
		}
		if digest != got {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", wantName, digest, got)
		}
		return nil
	}
	return fmt.Errorf("checksum file has no entry for %s", wantName)
}

// ExtractBinary returns the release executable bytes from archiveData.
// Unix releases ship as .tar.gz; Windows releases ship as .zip.
func ExtractBinary(archiveData []byte, goos, wantName string) ([]byte, error) {
	if goos == "windows" {
		return extractZipFile(archiveData, wantName)
	}
	return extractTarGzFile(archiveData, wantName)
}

func extractTarGzFile(tarGz []byte, wantName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return nil, fmt.Errorf("opening gzip archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Name == wantName {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("archive has no entry named %s", wantName)
}

func extractZipFile(zipData []byte, wantName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("opening zip archive: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != wantName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("opening zip entry %s: %w", wantName, err)
		}
		data, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return data, nil
	}
	return nil, fmt.Errorf("archive has no entry named %s", wantName)
}

// IsNewer reports whether latestTag (e.g. "v0.2.0") is a newer version than
// currentVersion (e.g. "0.1.0"). Non-numeric / missing components compare
// as 0, so pre-release suffixes like "-rc1" are ignored rather than
// misparsed.
func IsNewer(latestTag, currentVersion string) bool {
	latest := parseVersion(strings.TrimPrefix(latestTag, "v"))
	current := parseVersion(currentVersion)
	for i := 0; i < 3; i++ {
		if latest[i] != current[i] {
			return latest[i] > current[i]
		}
	}
	return false
}

func parseVersion(s string) [3]int {
	var v [3]int
	parts := strings.SplitN(s, ".", 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		v[i] = leadingInt(parts[i])
	}
	return v
}

// leadingInt parses the leading run of digits in s (e.g. "0" out of
// "0-rc1"), returning 0 if there is none.
func leadingInt(s string) int {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}
