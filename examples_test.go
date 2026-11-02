package enigoma

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleConfigsParse(t *testing.T) {
	var files []string
	err := filepath.WalkDir("examples", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example configs found")
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ParseSettings(data)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if _, err := NewFromSettings(s); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}
