package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mirzasaikatahmmed/gitshield/internal/audit"
	"github.com/mirzasaikatahmmed/gitshield/internal/config"
	"github.com/mirzasaikatahmmed/gitshield/internal/report"
	"github.com/mirzasaikatahmmed/gitshield/internal/scanner"
)

// parseArgs parses args against fs, allowing flags to appear before, after,
// or interspersed with positional arguments. The standard library's
// flag.FlagSet stops parsing at the first non-flag token, which would make
// `gitshield scan <path> --json` silently ignore --json — surprising for a
// CLI whose positional argument (repo URL / path) usually comes first.
func parseArgs(fs *flag.FlagSet, args []string) error {
	var flagArgs, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				continue // value is embedded (--flag=value); nothing more to consume
			}
			if f := fs.Lookup(name); f != nil {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					continue // boolean flag takes no following value
				}
			}
			if i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	// flagArgs contains only recognized flags and their values, so the
	// first Parse leaves no residue; this second call just makes the
	// collected positional arguments available via fs.Args()/fs.Arg().
	return fs.Parse(positional)
}

// confirmPhrase is the exact phrase a user must type (in addition to
// passing --force-unsafe) to override a HIGH-severity block. Deliberately
// not a simple y/N so an override can't happen by reflexive keypress.
const confirmPhrase = "I ACCEPT THE RISK"

type globalFlags struct {
	jsonOut      bool
	yes          bool   // auto-confirm MODERATE prompts (CI use)
	forceUnsafe  bool   // required to even attempt overriding HIGH
	confirmInput string // pre-supplied confirmation phrase, for non-interactive override
	configPath   string
	noAutoUpdate bool // skip the background auto-update check for this invocation
	deep         bool // also scan arbitrary top-level *.js/*.mjs/*.cjs files with the same heuristics
}

func loadEngine(gf globalFlags) (*scanner.Engine, config.Config, error) {
	cfgPath := gf.configPath
	if cfgPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, config.Config{}, err
		}
		cfgPath = p
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, config.Config{}, fmt.Errorf("loading config %s: %w", cfgPath, err)
	}
	sigs, err := cfg.EffectiveSignatures()
	if err != nil {
		return nil, config.Config{}, fmt.Errorf("loading signatures: %w", err)
	}
	eng := scanner.NewEngine(sigs)
	if cfg.Severity.HighHeuristicCount > 0 {
		eng.Thresholds.HighHeuristicCount = cfg.Severity.HighHeuristicCount
	}
	eng.Deep = gf.deep
	return eng, cfg, nil
}

// decision is the outcome of applying gitshield's severity policy.
type decision struct {
	proceed    bool
	overridden bool
	exitCode   int
}

// decide applies the CLEAN/MODERATE/HIGH policy, prompting interactively as
// needed. repoRef is used only for the printed report header and audit log.
func decide(gf globalFlags, res scanner.Result, repoRef string) decision {
	switch res.Severity {
	case scanner.Clean:
		return decision{proceed: true, exitCode: report.ExitClean}

	case scanner.Moderate:
		if !gf.jsonOut {
			report.PrintHuman(os.Stdout, res, repoRef)
		}
		if gf.yes || confirmYesNo(fmt.Sprintf("\nMODERATE risk detected in %s. Proceed anyway? [y/N] ", repoRef)) {
			return decision{proceed: true, exitCode: report.ExitModerateProceeded}
		}
		return decision{proceed: false, exitCode: report.ExitModerateProceeded}

	case scanner.High:
		if !gf.jsonOut {
			report.PrintHuman(os.Stdout, res, repoRef)
			fmt.Fprintln(os.Stderr, "\nHIGH severity: refusing to proceed automatically.")
		}
		if !gf.forceUnsafe {
			return decision{proceed: false, exitCode: report.ExitHighBlocked}
		}
		phrase := gf.confirmInput
		if phrase == "" {
			phrase = promptLine(fmt.Sprintf("Type %q to override and proceed anyway: ", confirmPhrase))
		}
		if strings.TrimSpace(phrase) != confirmPhrase {
			if !gf.jsonOut {
				fmt.Fprintln(os.Stderr, "confirmation phrase did not match; refusing to proceed.")
			}
			return decision{proceed: false, exitCode: report.ExitHighBlocked}
		}
		return decision{proceed: true, overridden: true, exitCode: report.ExitHighOverridden}

	default:
		return decision{proceed: false, exitCode: report.ExitHighBlocked}
	}
}

func confirmYesNo(prompt string) bool {
	ans := promptLine(prompt)
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes"
}

func promptLine(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func logAudit(action, repoRef string, res scanner.Result, d decision) {
	path, err := audit.DefaultPath()
	if err != nil {
		return
	}
	_ = audit.Append(path, audit.Entry{
		Timestamp:  time.Now().UTC(),
		Action:     action,
		RepoRef:    repoRef,
		User:       audit.CurrentUser(),
		Severity:   res.Severity.String(),
		Signatures: report.MatchedSignatureIDs(res),
		Overridden: d.overridden,
		Proceeded:  d.proceed,
	})
}

func emitReport(gf globalFlags, res scanner.Result, repoRef string, d decision) {
	if gf.jsonOut {
		_ = report.PrintJSON(os.Stdout, res, d.proceed, d.overridden, d.exitCode)
		return
	}
	if res.Severity == scanner.Clean {
		report.PrintHuman(os.Stdout, res, repoRef)
	}
	// MODERATE/HIGH reports were already printed inside decide() before the
	// prompt, so the user sees findings before being asked to confirm.
}
