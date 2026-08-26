// Package signatures defines the pluggable indicator-of-compromise (IOC)
// signature set used by the scanner, and loads the default embedded set
// plus any user-supplied overrides/additions from config.
package signatures

// Kind distinguishes an exact string/regex match from a behavioral heuristic.
type Kind string

const (
	// KindString is a verbatim substring match.
	KindString Kind = "string"
	// KindRegex is a regular-expression match.
	KindRegex Kind = "regex"
	// KindHeuristic is a named built-in heuristic implemented in the scanner
	// (long-line, child_process+eval, eth-address, worm-marker). The Pattern
	// field is ignored for heuristics; HeuristicName selects the check.
	KindHeuristic Kind = "heuristic"
)

// Heuristic names understood by the scanner's heuristic engine.
const (
	HeuristicLongLine      = "long-line"
	HeuristicSpawnEval     = "spawn-detached-eval"
	HeuristicEthAddress    = "eth-address"
	HeuristicGitignoreWorm = "gitignore-worm-marker"
)

// Signature is a single detection rule.
type Signature struct {
	ID            string `yaml:"id"`
	Kind          Kind   `yaml:"kind"`
	Pattern       string `yaml:"pattern,omitempty"`   // for KindString / KindRegex
	HeuristicName string `yaml:"heuristic,omitempty"` // for KindHeuristic
	Description   string `yaml:"description"`
	// Exact indicates this signature is a known campaign IOC (vs. a fuzzy
	// heuristic). Any exact match is automatically HIGH severity regardless
	// of heuristic-count thresholds.
	Exact bool `yaml:"exact"`
}

// Set is a named, versioned collection of signatures plus metadata about
// which files/paths they apply to.
type Set struct {
	Version    int         `yaml:"version"`
	Updated    string      `yaml:"updated"`
	Signatures []Signature `yaml:"signatures"`
}

// Merge returns a new Set combining s with extra, with extra's entries
// appended after s's (IDs are not deduplicated; later entries simply add
// more rules — an override-by-ID is intentionally not implemented since
// campaign IDs should be additive, not silently shadowed).
func (s Set) Merge(extra Set) Set {
	out := Set{
		Version:    s.Version,
		Updated:    s.Updated,
		Signatures: make([]Signature, 0, len(s.Signatures)+len(extra.Signatures)),
	}
	out.Signatures = append(out.Signatures, s.Signatures...)
	out.Signatures = append(out.Signatures, extra.Signatures...)
	return out
}
