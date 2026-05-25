// Runs the Rego unit tests for EVERY pack (packs/*/rules) through OPA's tester
// library, so all packs can be verified with `go test ./...` without installing
// the OPA CLI.
package rulestest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/tester"
)

func TestPackRegoRules(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "packs", "*", "rules", "*.rego"))
	if err != nil {
		t.Fatalf("glob packs: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no pack rego files found under packs/*/rules")
	}

	modules := map[string]*ast.Module{}
	for _, p := range matches {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		m, err := ast.ParseModule(p, string(src))
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		modules[p] = m
	}

	ch, err := tester.NewRunner().
		SetStore(inmem.New()).
		SetModules(modules).
		RunTests(context.Background(), nil)
	if err != nil {
		t.Fatalf("run tests: %v", err)
	}

	var ran int
	for res := range ch {
		ran++
		if res.Error != nil {
			t.Errorf("%s/%s errored: %v", res.Package, res.Name, res.Error)
			continue
		}
		if res.Fail {
			t.Errorf("%s/%s FAILED", res.Package, res.Name)
		} else {
			t.Logf("%s/%s passed", res.Package, res.Name)
		}
	}
	if ran == 0 {
		t.Fatal("no rego tests ran")
	}
}
