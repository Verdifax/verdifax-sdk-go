package verdifax

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every import path the docs show must be one a reader can compile: the
// module root or a directory in it. doc.go is what pkg.go.dev shows first.
func TestDocumentedImportsExist(t *testing.T) {
	mod, readErr := os.ReadFile("go.mod")
	if readErr != nil {
		t.Fatal(readErr)
	}
	module := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(string(mod), "\n", 2)[0], "module "))
	quoted := regexp.MustCompile(`"(` + regexp.QuoteMeta(module) + `[^"\s]*)"`)
	found := 0
	for _, name := range []string{"doc.go", "README.md"} {
		text, docErr := os.ReadFile(name)
		if docErr != nil {
			t.Fatal(docErr)
		}
		for _, m := range quoted.FindAllStringSubmatch(string(text), -1) {
			found++
			sub := strings.TrimPrefix(m[1], module)
			if sub == "" {
				continue
			}
			if info, statErr := os.Stat(filepath.Join(".", sub)); statErr != nil || !info.IsDir() {
				t.Errorf("%s imports %s, which is not a package in this module", name, m[1])
			}
		}
	}
	if found == 0 {
		t.Fatal("no documented import found; the scan is broken")
	}
}
