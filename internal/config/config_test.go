package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEffectiveSignaturesMergesDefaultAutoUpdatePath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	dir, err := Dir()
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	auto := `
version: 1
signatures:
  - id: auto-updated-campaign
    kind: string
    pattern: "AUTO-UPDATED-IOC"
    description: "fetched by gitshield update-signatures"
    exact: true
`
	if err := os.WriteFile(filepath.Join(dir, "signatures.yaml"), []byte(auto), 0o600); err != nil {
		t.Fatalf("writing default signatures.yaml: %v", err)
	}

	var c Config
	sigs, err := c.EffectiveSignatures()
	if err != nil {
		t.Fatalf("EffectiveSignatures: %v", err)
	}

	found := false
	for _, s := range sigs.Signatures {
		if s.ID == "auto-updated-campaign" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ~/.gitshield/signatures.yaml to be merged in even without an explicit signatures_file config, got %+v", sigs.Signatures)
	}
}

func TestEffectiveSignaturesWithoutDefaultFileIsJustDefaults(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	var c Config
	sigs, err := c.EffectiveSignatures()
	if err != nil {
		t.Fatalf("EffectiveSignatures: %v", err)
	}
	if len(sigs.Signatures) == 0 {
		t.Fatalf("expected embedded default signatures even with no config/overlay files")
	}
	for _, s := range sigs.Signatures {
		if s.ID == "auto-updated-campaign" {
			t.Fatalf("unexpected signature present with no overlay file written")
		}
	}
}

func TestLoadParsesDashboardURL(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(path, []byte(`dashboard_url: "https://gitshield.saikat.com.bd"`+"\n"), 0o600); err != nil {
		t.Fatalf("writing config.yaml: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DashboardURL != "https://gitshield.saikat.com.bd" {
		t.Fatalf("expected dashboard_url to be parsed, got %q", c.DashboardURL)
	}
}

func TestLoadDefaultsDashboardURLToEmpty(t *testing.T) {
	var c Config
	if c.DashboardURL != "" {
		t.Fatalf("expected DashboardURL to default to empty (opt-in only), got %q", c.DashboardURL)
	}
}

func TestIsAllowlisted(t *testing.T) {
	c := Config{Allowlist: []string{"https://github.com/org/repo.git"}}
	if !c.IsAllowlisted("https://github.com/org/repo") {
		t.Fatalf("expected trailing .git to be normalized away")
	}
	if c.IsAllowlisted("https://github.com/org/other") {
		t.Fatalf("expected non-matching repo to not be allowlisted")
	}
}
