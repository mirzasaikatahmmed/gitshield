# gitshield

Pre-clone/pull malware scanner for the config-file supply-chain attack
described at [saikat.com.bd/blog/github-config-malware-prevention](https://saikat.com.bd/blog/github-config-malware-prevention):
obfuscated JavaScript appended after the legitimate `export` in
`eslint.config.*`, `postcss.config.*`, `prettier.config.*`,
`tailwind.config.*`, and `.eslintrc*` files. The payload only runs when
Node loads these files — during `npm install`, an IDE's linter, or
`npm run dev`/`build` — **not** during `git clone`/`git pull` themselves.
That gap is the window gitshield uses: it clones into quarantine / fetches
without merging, scans, and only then lets the content touch anywhere a
build tool could load it.

This is a local, per-developer complement to CI-based scanning
(`check-malware-configs.mjs` + branch protection) — not a replacement for
it, and not a general dependency/lockfile supply-chain scanner.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/mirzasaikatahmmed/gitshield/main/install.sh | sh
```

Downloads the right release binary for your OS/arch, verifies its checksum,
and installs it to `~/.local/bin/gitshield` (override with
`GITSHIELD_INSTALL_DIR`). Or:

```sh
go install github.com/mirzasaikatahmmed/gitshield/cmd/gitshield@latest
```

Or download a prebuilt binary yourself from the
[Releases](https://github.com/mirzasaikatahmmed/gitshield/releases) page
(linux/amd64, linux/arm64, darwin/amd64, darwin/arm64), then run
`gitshield install` to put it on your `PATH` and set up `~/.gitshield`.
gitshield is a single static Go binary with no runtime dependencies of its
own; it shells out to your existing `git` install to do the actual
clone/fetch/merge.

```sh
gitshield install [--prefix <dir>]      # copy this binary onto your PATH (default ~/.local/bin)
gitshield update [--check] [--force]    # self-update to the latest GitHub release, in place
gitshield uninstall [--purge]           # remove the binary (--purge also removes ~/.gitshield)
```

`gitshield update` checks the GitHub Releases API for a newer tag,
downloads the release asset for your OS/arch, verifies it against the
published checksum, and atomically replaces the running binary — safe to
run from a cron job or a shell alias. `--check` only reports whether an
update is available (useful for scripting) without installing it. This is
separate from `gitshield update-signatures`, which only refreshes the IOC
signature set, not the binary itself.

No working gitshield binary yet? `uninstall.sh` mirrors `gitshield
uninstall` for that case:

```sh
curl -fsSL https://raw.githubusercontent.com/mirzasaikatahmmed/gitshield/main/uninstall.sh | sh -s -- --purge
```

## Usage

```sh
# Scan-then-clone: scans a quarantine copy before it ever lands at ./repo
gitshield clone https://github.com/org/repo.git

# Inside an existing repo: fetches without merging, scans the incoming
# ref, and only fast-forwards if it's safe
gitshield pull

# Audit a directory (or an already-cloned repo) you didn't get via gitshield
gitshield scan .

# Also walk recent commit history — old commits can carry the payload
# even after HEAD has been cleaned up
gitshield scan . --history

# CI-friendly JSON output
gitshield scan . --json
```

Drop-in alias for muscle memory:

```sh
alias git-safe-clone="gitshield clone"
```

### Severity and exit codes

| Severity | Meaning                                                    | Behavior                                                          | Exit code |
|----------|-------------------------------------------------------------|---------------------------------------------------------------------|-----------|
| CLEAN    | No signature or heuristic matches                           | Proceeds automatically                                              | `0`       |
| MODERATE | Exactly one heuristic hit in a file (no exact IOC match)     | Prints findings, asks `y/N` before proceeding (`--yes` to auto-confirm) | `1` |
| HIGH     | Any exact known-IOC match, or 2+ heuristic hits in one file  | Refuses automatically. Override requires **both** `--force-unsafe` and typing the exact phrase `I ACCEPT THE RISK` (or `--confirm-phrase` for scripted/CI use) | `2` blocked, `3` if overridden |

Every scan is appended to `~/.gitshield/audit.log` (one JSON object per
line: timestamp, action, repo, user, severity, matched signatures,
whether it was overridden). Overrides are always logged, override or not.

### Auto-update

`clone`/`pull`/`scan` check at most once every 24 hours (tracked via
`~/.gitshield/last-auto-update-check`) whether a newer gitshield release or
IOC signature set is available, and apply it automatically when online:

- **Binary** — always checked; if a newer release exists, it's downloaded,
  checksum-verified, and swapped in atomically. Doesn't affect the run in
  progress (the old binary stays loaded in memory) — takes effect next
  invocation.
- **Signatures** — only checked if `update_signatures_url` and
  `update_signatures_pubkey` are set in config.yaml (gitshield never
  contacts an unpinned source on its own). If updated, the fresh
  signatures are written to `~/.gitshield/signatures.yaml` and used
  immediately, in that same scan.

It's entirely best-effort and silent on failure — offline, rate-limited,
no write permission, whatever — it never blocks or fails the command that
triggered it. Disable it persistently with `disable_auto_update: true` in
config.yaml, or for one run with `--no-auto-update`. `gitshield update` /
`update-signatures` remain available to force either one on demand,
regardless of this schedule.

### Detection rules

Signatures are pluggable and versioned (`internal/signatures/default.yaml`,
embedded in the binary at build time), not hardcoded string checks
scattered through the code. The default set ships with the known IOCs from
the campaign writeup:

- Exact string matches: campaign ID, `global.i=`/`global._V`/`global._H`/`global._H2`
  runtime markers, packed-footer signatures, `x-payload-b64` /
  `/0x/cls` / `/0x/ls` payload markers, the known C2 Ethereum address,
  and the `temp_auto_push.bat` / `temp_interactive_push.bat` worm markers.
- Heuristics: a line over ~2000 chars in a target config file (packed
  payload signal), `child_process` spawn with `detached: true` combined
  with `eval`/a dynamic `require`/`import` of remote content, an
  Ethereum-address-shaped string in a file with no legitimate reason to
  have one, and a `.gitignore` referencing the worm's batch files.

Any exact match, or 2+ heuristic hits in the same file, is HIGH. Exactly
one heuristic hit is MODERATE. See `internal/signatures/default.yaml` for
the full set and `internal/scanner/match.go` for how heuristics are
implemented.

## Configuration

`~/.gitshield/config.yaml` (see [`config.example.yaml`](config.example.yaml)
for the full annotated reference):

```yaml
allowlist:
  - https://github.com/your-org/your-trusted-repo.git

severity:
  high_heuristic_count: 2   # 2+ heuristic hits in one file => HIGH

signatures_file: ~/.gitshield/signatures.yaml   # merged on top of the defaults

update_signatures_url: "https://raw.githubusercontent.com/your-org/gitshield-signatures/main/signatures.yaml"
update_signatures_pubkey: "<64-hex-char ed25519 public key>"
```

- **Allowlist** — opt-in only, never populated by default. Repos on it
  skip scanning entirely for both `clone` and `pull`.
- **Custom signatures** — add new campaign IDs without recompiling, either
  inline under `signatures:` or via `signatures_file:` (merged on top of
  the embedded defaults; nothing is silently overridden by ID).
- **Severity threshold** — tune how many heuristic hits in one file
  escalate to HIGH. Exact IOC matches always escalate regardless.

### Adding a custom signature

```yaml
signatures:
  version: 1
  updated: "2026-08-27"
  signatures:
    - id: my-org-2026-08-campaign
      kind: string          # string | regex | heuristic
      pattern: "SOME-NEW-CAMPAIGN-MARKER"
      description: "Reported by our SOC, 2026-08-27"
      exact: true            # true => any match alone is HIGH
```

### Updating signatures

```sh
gitshield update-signatures
```

Fetches `update_signatures_url` plus a detached signature at
`<url>.sig` (a hex-encoded ed25519 signature of the file's raw bytes),
verifies it against `update_signatures_pubkey`, and only then writes
`~/.gitshield/signatures.yaml`. Refuses to run at all if no public key is
pinned — an unauthenticated update channel would just be a new attack
vector for the same class of campaign this tool defends against.

## How the pre-flight scan actually keeps you safe

- `gitshield clone` clones into a fresh temp directory first — never your
  real destination — scans it, and only `os.Rename`s it into place if the
  severity policy allows proceeding. On block/abort the quarantine
  directory is deleted; nothing is ever left at the destination path.
- `gitshield pull` runs `git fetch` (updates remote-tracking refs only)
  and scans the *incoming* ref's tree via `git show <ref>:<path>` —
  your working tree and local branch are never touched until the fetched
  content has been scanned and cleared. A block leaves `HEAD` and the
  working tree exactly as they were.

Since the payload only executes when something loads the JS file, having
scanned content briefly on disk in quarantine (never `require`'d,
`import`'d, or opened by an IDE that executes config files) does not
trigger it.

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

Fixtures for the scanner's unit tests live under
`internal/scanner/testdata/{clean,infected}/` — synthesized to match the
patterns described in the writeup, not real captured malware.

## Non-goals

- Not a general npm/dependency supply-chain scanner (lockfile/postinstall
  attacks are explicitly out of scope, per the source writeup).
- Not a replacement for CI-based scanning + branch protection — this is
  the complementary local, pre-clone layer for individual dev machines.
