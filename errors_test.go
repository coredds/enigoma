package enigoma

import "testing"

func TestCharError(t *testing.T) {
	got := (&CharError{Rune: 'é', Offset: 4}).Error()
	want := `character 'é' at offset 4 is not in the alphabet`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
