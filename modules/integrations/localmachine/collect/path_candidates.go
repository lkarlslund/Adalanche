package collect

import "strings"

// servicePathCandidates identifies ambiguous unquoted executable prefixes only.
// It does not execute, resolve or claim writability of any candidate.
func servicePathCandidates(command string) []string {
	command = strings.TrimSpace(command)
	if command == "" || strings.HasPrefix(command, `"`) {
		return nil
	}
	end := strings.Index(strings.ToLower(command), ".exe")
	if end < 0 {
		return nil
	}
	path := command[:end+4]
	var candidates []string
	for i, c := range path {
		if c == ' ' {
			candidates = append(candidates, path[:i]+".exe")
			if len(candidates) == 16 {
				break
			}
		}
	}
	return candidates
}
