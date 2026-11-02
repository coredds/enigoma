// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"errors"
	"io/fs"
	"strings"
)

// suggestConfigFixes returns hints for a configuration loading error.
func suggestConfigFixes(err error) string {
	var tips []string
	switch msg := err.Error(); {
	case errors.Is(err, fs.ErrNotExist):
		tips = append(tips, "check the file path")
	case strings.Contains(msg, "schema v1"):
		tips = append(tips,
			"old keys cannot be used: the stepping fix in 0.7 changes the cipher",
			"generate a new key: enigoma keygen --output new-key.json",
			"or encrypt with: enigoma encrypt --text \"...\" --auto-config new-key.json")
	case strings.Contains(msg, "parse settings"):
		tips = append(tips, "the file is not valid JSON; regenerate it with enigoma keygen")
	default:
		tips = append(tips, "regenerate the configuration with enigoma keygen")
	}
	return "  • " + strings.Join(tips, "\n  • ")
}
