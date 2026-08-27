package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdAddBlocksInfectedTargetFile(t *testing.T) {
	dir := setupAddTestRepo(t)
	infected := filepath.Join(dir, "postcss.config.mjs")
	payload := "export default config;" + strings.Repeat(" ", 2000) + `global.i="A8-5741";':443/0x/ls';` + "\n"
	if err := os.WriteFile(infected, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	code := runGitshieldInDir(t, dir, "add", "--no-auto-update", ".")
	if code != 2 {
		t.Fatalf("expected exit 2 (HIGH blocked), got %d", code)
	}
	out := runGitOut(t, dir, "status", "--porcelain", "postcss.config.mjs")
	if out != "?? postcss.config.mjs\n" {
		t.Fatalf("file should remain unstaged, status=%q", out)
	}
}

func TestCmdAddAllowsCleanTargetFile(t *testing.T) {
	dir := setupAddTestRepo(t)
	clean := filepath.Join(dir, "postcss.config.mjs")
	if err := os.WriteFile(clean, []byte("export default { plugins: [] };\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code := runGitshieldInDir(t, dir, "add", "--no-auto-update", ".")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	out := runGitOut(t, dir, "status", "--porcelain", "postcss.config.mjs")
	if out != "A  postcss.config.mjs\n" && out != "A postcss.config.mjs\n" {
		t.Fatalf("expected staged postcss.config.mjs, status=%q", out)
	}
}

func setupAddTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "t@test.com")
	runGit(t, dir, "config", "user.name", "test")
	return dir
}

func runGitshieldInDir(t *testing.T, dir string, args ...string) int {
	t.Helper()
	bin := buildGitshieldBinary(t)
	home := t.TempDir()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, _ := cmd.CombinedOutput()
	t.Log(string(out))
	return cmd.ProcessState.ExitCode()
}

func buildGitshieldBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "gitshield")
	cmd := exec.Command("go", "build", "-o", out, ".")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build gitshield: %v\n%s", err, combined)
	}
	return out
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", args, err, combined)
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
