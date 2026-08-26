package signatures

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed default.yaml
var defaultYAML []byte

// Default returns the embedded default signature set shipped with the
// gitshield binary. It is parsed fresh on every call so callers may freely
// mutate the result.
func Default() (Set, error) {
	var s Set
	if err := yaml.Unmarshal(defaultYAML, &s); err != nil {
		return Set{}, err
	}
	return s, nil
}

// ParseYAML parses a signature set from raw YAML bytes (used for
// user-supplied custom signature files and update-signatures downloads).
func ParseYAML(data []byte) (Set, error) {
	var s Set
	if err := yaml.Unmarshal(data, &s); err != nil {
		return Set{}, err
	}
	return s, nil
}
