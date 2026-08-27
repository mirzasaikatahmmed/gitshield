package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAddDryRunPaths(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init")
	writeFile(t, dir, "postcss.config.mjs", "export default {}\n")
	writeFile(t, dir, "README.md", "# ok\n")
	writeFile(t, dir, ".gitignore", "node_modules/\n")

	paths, err := AddDryRunPaths(dir, []string{"."})
	if err != nil {
		t.Fatalf("AddDryRunPaths: %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected 3 paths, got %v", paths)
	}
}

func TestAddStagesAfterDryRun(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init")
	writeFile(t, dir, "README.md", "# ok\n")

	if err := Add(dir, []string{"."}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	out := runGitOut(t, dir, "status", "--porcelain")
	if out != "A  README.md\n" && out != "A README.md\n" {
		t.Fatalf("unexpected status after add: %q", out)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=t@test.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=t@test.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", args, err, out)
	}
}

func runGitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", args, err)
	}
	return string(out)
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
