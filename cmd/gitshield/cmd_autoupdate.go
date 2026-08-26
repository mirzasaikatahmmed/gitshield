package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/mirzasaikatahmmed/gitshield/internal/autoupdate"
	"github.com/mirzasaikatahmmed/gitshield/internal/config"
	"github.com/mirzasaikatahmmed/gitshield/internal/selfupdate"
)

// autoUpdateInterval bounds how often maybeAutoUpdate actually hits the
// network, regardless of how many clone/pull/scan invocations happen in
// between — tracked via internal/autoupdate's timestamp file.
const autoUpdateInterval = 24 * time.Hour

// maybeAutoUpdate runs gitshield's background auto-update check at the
// start of clone/pull/scan: refreshes the IOC signature set (if
// update_signatures_url/pubkey are configured) and self-updates the binary
// if a newer release exists — but at most once per autoUpdateInterval, and
// only when the network actually cooperates. It is best-effort and silent
// on any failure (offline, rate-limited, no permission to write, etc.):
// this is a convenience, never allowed to fail or delay the command that
// triggered it. `gitshield update` / `update-signatures` remain available
// to force either one on demand regardless of the schedule.
func maybeAutoUpdate(gf globalFlags) {
	if gf.noAutoUpdate {
		return
	}

	cfgPath := gf.configPath
	if cfgPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return
		}
		cfgPath = p
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.DisableAutoUpdate {
		return
	}

	dir, err := config.Dir()
	if err != nil {
		return
	}
	if !autoupdate.IsDue(dir, autoUpdateInterval) {
		return
	}
	// Record the attempt regardless of outcome, so an offline machine gets
	// re-checked once per interval rather than on every single invocation.
	defer func() { _ = autoupdate.RecordNow(dir) }()

	autoUpdateSignatures(cfg)
	autoUpdateBinary()
}

// autoUpdateSignatures fetches and verifies a fresh signature set, writing
// it to ~/.gitshield/signatures.yaml (picked up by EffectiveSignatures for
// this very run) only if it actually changed. No-ops entirely if
// update_signatures_url/pubkey aren't configured — gitshield never
// contacts an unpinned/unconfigured source on its own.
func autoUpdateSignatures(cfg config.Config) {
	if cfg.UpdateSignaturesURL == "" || cfg.UpdateSignaturesPubKey == "" {
		return
	}
	data, err := fetchVerifiedSignatures(cfg)
	if err != nil {
		return
	}
	if dest, err := config.DefaultSignaturesPath(); err == nil {
		if existing, err := os.ReadFile(dest); err == nil && bytes.Equal(existing, data) {
			return // unchanged since last check — nothing to write or announce
		}
	}
	if _, err := writeSignatures(data); err != nil {
		return
	}
	fmt.Fprintln(os.Stderr, "gitshield: auto-updated signatures (used for this run)")
}

// autoUpdateBinary self-updates gitshield if a newer release is published.
// Doesn't affect the process currently running (the old binary stays
// loaded in memory) — only the next invocation picks up the new one.
func autoUpdateBinary() {
	rel, err := selfupdate.FetchLatest(selfupdate.DefaultRepo)
	if err != nil {
		return
	}
	if !selfupdate.IsNewer(rel.TagName, version) {
		return
	}
	binData, err := fetchVerifiedBinary(rel)
	if err != nil {
		return
	}
	execPath, err := runningExecutablePath()
	if err != nil {
		return
	}
	if err := replaceExecutable(execPath, binData); err != nil {
		return // e.g. no write permission to the install dir — silently skip
	}
	fmt.Fprintf(os.Stderr, "gitshield: auto-updated v%s -> %s (takes effect next run)\n", version, rel.TagName)
}
