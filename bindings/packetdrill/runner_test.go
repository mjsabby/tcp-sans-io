// Test runner that discovers .pkt files under scripts/ and runs each one
// as a Go subtest. To add a new test, drop a .pkt file in scripts/.

package packetdrill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScripts(t *testing.T) {
	entries, err := os.ReadDir("scripts")
	if err != nil {
		t.Fatalf("read scripts dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pkt") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pkt")
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("scripts", e.Name())
			script, err := ParseFile(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := RunScript(script); err != nil {
				t.Fatalf("%v", err)
			}
		})
	}
}
