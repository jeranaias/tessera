// Runs the Rego unit tests in ../rules through OPA's tester library, so the
// rules pack can be verified with `go test ./...` without installing the OPA CLI.
package rulestest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/tester"
)

func TestRegoRules(t *testing.T) {
	const dir = "../rules"
	modules := map[string]*ast.Module{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read rules dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		m, err := ast.ParseModule(e.Name(), string(src))
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		modules[e.Name()] = m
	}

	ctx := context.Background()
	ch, err := tester.NewRunner().
		SetStore(inmem.New()).
		SetModules(modules).
		RunTests(ctx, nil)
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
