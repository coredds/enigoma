// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package enigoma

import "fmt"

// CharError reports an input character that is not part of the machine's alphabet.
type CharError struct {
	Rune   rune // the offending character
	Offset int  // rune offset (not byte offset) in the input
}

func (e *CharError) Error() string {
	return fmt.Sprintf("character %q at offset %d is not in the alphabet", e.Rune, e.Offset)
}
