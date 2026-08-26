// Package git wraps the system git binary to implement gitshield's
// scan-before-touch-the-working-tree workflow: clone into a quarantine
// directory (not the final destination) and fetch-without-merge for pull,
// so the scanner always inspects content before it lands anywhere a build
// tool, IDE, or `npm install` could load it.
package git

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runtime error returned when the git binary itself cannot be found — the
// one external dependency gitshield has, since it wraps the real git CLI.
var ErrGitNotFound = fmt.Errorf("git executable not found in PATH")

func requireGit() error {
	if _, err := exec.LookPath("git"); err != nil {
		return ErrGitNotFound
	}
	return nil
}

func run(dir string, args ...string) ([]byte, error) {
	if err := requireGit(); err != nil {
		return nil, err
	}
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}

// IsGitRepo reports whether dir is (the top level of) a git working tree.
func IsGitRepo(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// CloneQuarantine clones repoURL into a freshly created temp directory
// (never the user's final destination) so the scanner can inspect it before
// anything is placed where a build tool would load it. Callers must call
// RemoveQuarantine if they decide not to proceed.
func CloneQuarantine(repoURL string) (string, error) {
	tmp, err := os.MkdirTemp("", "gitshield-clone-*")
	if err != nil {
		return "", err
	}
	// git refuses to clone into a non-empty dir; MkdirTemp's dir is empty,
	// but git also wants the target to not already exist as a repo, which
	// is guaranteed here since it's brand new.
	if _, err := run("", "clone", "--quiet", "--", repoURL, tmp); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	return tmp, nil
}

// RemoveQuarantine deletes a quarantine directory created by CloneQuarantine.
// Safe to call on abort — the directory was created by gitshield itself and
// nothing has been placed at the user's real destination yet.
func RemoveQuarantine(dir string) error {
	if dir == "" || !strings.Contains(filepath.Base(dir), "gitshield-clone-") {
		return fmt.Errorf("refusing to remove non-quarantine path: %s", dir)
	}
	return os.RemoveAll(dir)
}

// MoveIntoPlace relocates a scanned quarantine directory to its final
// destination. Refuses to overwrite an existing path.
func MoveIntoPlace(quarantineDir, destDir string) error {
	if _, err := os.Stat(destDir); err == nil {
		return fmt.Errorf("destination already exists: %s", destDir)
	}
	return os.Rename(quarantineDir, destDir)
}

// DeriveDestDir mimics `git clone <url>`'s default target-directory naming.
func DeriveDestDir(repoURL string) string {
	base := strings.TrimSuffix(strings.TrimSuffix(repoURL, "/"), ".git")
	if idx := strings.LastIndexAny(base, "/:"); idx != -1 {
		base = base[idx+1:]
	}
	if base == "" {
		base = "repo"
	}
	return base
}

// Fetch updates the remote-tracking refs of repoDir without touching the
// working tree or any local branch.
func Fetch(repoDir, remoteName string) error {
	if remoteName == "" {
		remoteName = "origin"
	}
	_, err := run(repoDir, "fetch", "--quiet", remoteName)
	return err
}

// UpstreamRef returns the full ref of the current branch's upstream
// (e.g. "refs/remotes/origin/main"), used as the scan target after Fetch.
func UpstreamRef(repoDir string) (string, error) {
	out, err := run(repoDir, "rev-parse", "--symbolic-full-name", "@{u}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// RemoteURL returns the URL configured for remoteName (default "origin").
func RemoteURL(repoDir, remoteName string) (string, error) {
	if remoteName == "" {
		remoteName = "origin"
	}
	out, err := run(repoDir, "remote", "get-url", remoteName)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ListTreeFiles lists every file path in ref's tree.
func ListTreeFiles(repoDir, ref string) ([]string, error) {
	out, err := run(repoDir, "ls-tree", "-r", "--name-only", ref)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if l != "" {
			files = append(files, l)
		}
	}
	return files, nil
}

// ShowBlob returns the content of path as it exists at ref.
func ShowBlob(repoDir, ref, path string) ([]byte, error) {
	return run(repoDir, "show", ref+":"+path)
}

// FastForwardMerge fast-forwards the current branch to ref. Fails (does not
// fall back to a merge commit) if a fast-forward isn't possible, which is
// the only case gitshield's `pull` is meant to handle automatically.
func FastForwardMerge(repoDir, ref string) error {
	_, err := run(repoDir, "merge", "--ff-only", "--quiet", ref)
	return err
}

// ListCommits returns up to limit commit hashes (most recent first) that
// touched any of pathspecs, for `scan --history`.
func ListCommits(repoDir string, pathspecs []string, limit int) ([]string, error) {
	args := []string{"log", fmt.Sprintf("-n%d", limit), "--format=%H"}
	if len(pathspecs) > 0 {
		args = append(args, "--")
		args = append(args, pathspecs...)
	}
	out, err := run(repoDir, args...)
	if err != nil {
		return nil, err
	}
	var hashes []string
	for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if l != "" {
			hashes = append(hashes, l)
		}
	}
	return hashes, nil
}
