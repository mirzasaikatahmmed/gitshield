// Command gitshield wraps git clone/pull with a mandatory pre-flight scan
// for the config-file-appended-payload malware campaign described at
// https://saikat.com.bd/blog/github-config-malware-prevention — see the
// package doc comments under internal/ for the detection design.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

// version identifies this build for `gitshield version` and for comparing
// against release tags in the update/auto-update paths. It is never
// bumped by hand:
//   - Release binaries get it injected by release.yml's
//     -ldflags="-X main.version=<tag, v-stripped>", set from the git tag
//     that triggered the build — the release process is the only thing
//     that ever sets a real version.
//   - `go install .../gitshield@vX.Y.Z` leaves the ldflags value at its
//     zero state ("dev"); init() then falls back to the module version Go
//     itself records in the binary via runtime/debug.
//   - A plain local `go build`/`go run` with neither reports "dev".
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = strings.TrimPrefix(info.Main.Version, "v")
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}

	switch args[0] {
	case "clone":
		return cmdClone(args[1:])
	case "pull":
		return cmdPull(args[1:])
	case "scan":
		return cmdScan(args[1:])
	case "update-signatures":
		return cmdUpdateSignatures(args[1:])
	case "install":
		return cmdInstall(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	case "update":
		return cmdUpdate(args[1:])
	case "-h", "--help", "help":
		printUsage()
		return 0
	case "-v", "--version", "version":
		fmt.Println("gitshield " + version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "gitshield: unknown command %q\n\n", args[0])
		printUsage()
		return 2
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `gitshield — pre-clone/pull malware scanner for config-file supply chain attacks

Usage:
  gitshield clone <repo-url> [flags]     Scan before cloning into a new directory
  gitshield pull [flags]                 Scan the incoming ref before fast-forwarding
  gitshield scan <path> [flags]          Scan an already-cloned directory
  gitshield update-signatures [flags]    Fetch the latest IOC signature set
  gitshield install [flags]              Install this binary onto your PATH
  gitshield uninstall [flags]            Remove the installed binary
  gitshield update [flags]               Self-update gitshield to the latest release
  gitshield version                      Print the version

Common flags:
  --json                Emit machine-readable JSON instead of a human report
  --config <path>        Use an alternate config file (default ~/.gitshield/config.yaml)
  --yes, -y               Auto-confirm MODERATE-severity prompts (does NOT bypass HIGH)
  --force-unsafe          Required (with --confirm-phrase or an interactive prompt) to
                          proceed past a HIGH-severity block
  --confirm-phrase <s>    Non-interactive override phrase for HIGH severity
                          (must exactly equal "I ACCEPT THE RISK")
  --no-auto-update        Skip this run's background auto-update check (see below)

Auto-update:
  clone/pull/scan check at most once every 24h (silent, best-effort, never
  blocks or fails the command) whether a newer gitshield release or IOC
  signature set is available, and applies it automatically when online.
  Signature auto-update only runs if update_signatures_url/pubkey are set
  in config.yaml; binary self-update always checks. Disable persistently
  with disable_auto_update: true in config.yaml, or per-run with
  --no-auto-update. gitshield update / update-signatures still work on
  demand regardless of this schedule.

Exit codes:
  0  clean, proceeded
  1  moderate risk, warning shown (proceeded or declined after prompt)
  2  high severity, blocked
  3  high severity, overridden with --force-unsafe

Examples:
  gitshield clone https://github.com/org/repo.git
  gitshield pull
  gitshield scan . --history
  gitshield install                      # copy this binary onto your PATH (~/.local/bin)
  gitshield update --check               # see if a newer release exists
  gitshield uninstall --purge            # remove the binary and ~/.gitshield
  alias git-safe-clone="gitshield clone"
`)
}

// parseCommonFlags registers the shared flags on fs and returns the struct
// they populate.
func parseCommonFlags(fs *flag.FlagSet) *globalFlags {
	gf := &globalFlags{}
	fs.BoolVar(&gf.jsonOut, "json", false, "emit JSON output")
	fs.BoolVar(&gf.yes, "yes", false, "auto-confirm MODERATE prompts")
	fs.BoolVar(&gf.yes, "y", false, "auto-confirm MODERATE prompts (shorthand)")
	fs.BoolVar(&gf.forceUnsafe, "force-unsafe", false, "allow overriding a HIGH-severity block")
	fs.StringVar(&gf.confirmInput, "confirm-phrase", "", "non-interactive HIGH-override confirmation phrase")
	fs.StringVar(&gf.configPath, "config", "", "path to config.yaml (default ~/.gitshield/config.yaml)")
	fs.BoolVar(&gf.noAutoUpdate, "no-auto-update", false, "skip the background auto-update check for this run")
	return gf
}
