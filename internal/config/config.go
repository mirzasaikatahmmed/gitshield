// Package config loads gitshield's user configuration from
// ~/.gitshield/config.yaml: custom/additional signatures, the repo
// allowlist, severity threshold overrides, and the signature-update source.
package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mirzasaikatahmmed/gitshield/internal/signatures"
)

// Config is the on-disk user configuration.
type Config struct {
	// Signatures, if set, are merged on top of the embedded default set.
	// Either inline (Signatures.Signatures) or loaded from a separate file
	// via SignaturesFile.
	Signatures     signatures.Set `yaml:"signatures"`
	SignaturesFile string         `yaml:"signatures_file"`

	// Allowlist is a set of repo URLs (or, for `pull`, local repo paths)
	// the user has explicitly opted to trust and skip scanning entirely.
	// Never populated by default — opt-in only.
	Allowlist []string `yaml:"allowlist"`

	Severity SeverityConfig `yaml:"severity"`

	// UpdateSignaturesURL is where `gitshield update-signatures` fetches
	// the latest signature set from (e.g. a raw Gist/repo URL).
	UpdateSignaturesURL string `yaml:"update_signatures_url"`
	// UpdateSignaturesPubKey is a hex-encoded ed25519 public key used to
	// verify the detached signature (<url>.sig) of the downloaded signature
	// file. If empty, update-signatures falls back to SHA-256 checksum
	// verification against UpdateSignaturesSHA256 and refuses to run if
	// neither is configured.
	UpdateSignaturesPubKey string `yaml:"update_signatures_pubkey"`

	// DisableAutoUpdate opts out of gitshield's automatic background
	// update check (signatures + binary, at most once per 24h, only when
	// update_signatures_url/pubkey are configured and the network is
	// reachable). `gitshield update` / `update-signatures` remain
	// available manually either way. Default: auto-update enabled.
	DisableAutoUpdate bool `yaml:"disable_auto_update"`
}

// SeverityConfig lets users tune the heuristic-count threshold that
// escalates a file from MODERATE to HIGH. Exact-signature matches always
// escalate to HIGH regardless of this setting.
type SeverityConfig struct {
	HighHeuristicCount int `yaml:"high_heuristic_count"`
}

// DefaultPath returns ~/.gitshield/config.yaml.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".gitshield", "config.yaml"), nil
}

// Dir returns ~/.gitshield, creating it if necessary.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".gitshield")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// DefaultSignaturesPath returns ~/.gitshield/signatures.yaml — the fixed
// destination `gitshield update-signatures` (manual or automatic) writes
// to. EffectiveSignatures always considers this path if present, even when
// SignaturesFile points somewhere else, so an automatic update actually
// takes effect without requiring a config edit.
func DefaultSignaturesPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "signatures.yaml"), nil
}

// Load reads the config file at path. A missing file is not an error — it
// returns a zero-value Config (no custom signatures, no allowlist, no
// overrides), matching gitshield's ship-with-sane-defaults behavior.
func Load(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

// IsAllowlisted reports whether repoRef (a clone URL or local path) matches
// an entry in the allowlist. Matching is exact or, for URLs, tolerant of a
// trailing ".git" / trailing slash difference.
func (c Config) IsAllowlisted(repoRef string) bool {
	norm := normalizeRepoRef(repoRef)
	for _, entry := range c.Allowlist {
		if normalizeRepoRef(entry) == norm {
			return true
		}
	}
	return false
}

func normalizeRepoRef(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	return strings.ToLower(s)
}

// EffectiveSignatures returns the embedded default signature set merged
// with any config-supplied custom signatures (inline and/or from
// SignaturesFile), plus ~/.gitshield/signatures.yaml if present — the fixed
// destination `gitshield update-signatures` writes to, considered
// automatically even when SignaturesFile isn't set to it explicitly, so an
// automatic signature update actually affects the next scan.
func (c Config) EffectiveSignatures() (signatures.Set, error) {
	base, err := signatures.Default()
	if err != nil {
		return signatures.Set{}, err
	}

	merged := base
	if len(c.Signatures.Signatures) > 0 {
		merged = merged.Merge(c.Signatures)
	}

	seen := map[string]bool{}
	mergeFile := func(path string) error {
		path = expandHome(path)
		if path == "" || seen[path] {
			return nil
		}
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		extra, err := signatures.ParseYAML(data)
		if err != nil {
			return err
		}
		merged = merged.Merge(extra)
		return nil
	}

	if c.SignaturesFile != "" {
		// Explicitly configured: a missing file here is a config error,
		// not a silent no-op — surface it, unlike the default auto-update
		// path below.
		data, err := os.ReadFile(expandHome(c.SignaturesFile))
		if err != nil {
			return signatures.Set{}, err
		}
		extra, err := signatures.ParseYAML(data)
		if err != nil {
			return signatures.Set{}, err
		}
		seen[expandHome(c.SignaturesFile)] = true
		merged = merged.Merge(extra)
	}
	if defaultPath, err := DefaultSignaturesPath(); err == nil {
		if err := mergeFile(defaultPath); err != nil {
			return signatures.Set{}, err
		}
	}

	return merged, nil
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~"))
}
