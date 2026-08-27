package git

import (
	"regexp"
	"strings"
)

var addDryRunLine = regexp.MustCompile(`^add '(.*)'$`)

// Add runs git add in repoDir with the given arguments (flags and pathspecs).
func Add(repoDir string, args []string) error {
	cmdArgs := append([]string{"add"}, args...)
	_, err := run(repoDir, cmdArgs...)
	return err
}

// AddDryRunPaths returns repo-relative paths that git add would stage for the
// given git-add arguments. It uses git add -n --verbose, so flags like -A,
// -u, and pathspecs behave the same as a real add.
func AddDryRunPaths(repoDir string, args []string) ([]string, error) {
	cmdArgs := append([]string{"add", "-n", "--verbose"}, args...)
	out, err := run(repoDir, cmdArgs...)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := addDryRunLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		p := m[1]
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths, nil
}
