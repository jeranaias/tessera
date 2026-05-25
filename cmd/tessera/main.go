// Command tessera is a domain-agnostic conformance engine. It evaluates a
// manifest against a "pack" — a self-contained bundle of a rules pack (Rego) and
// a reusable library — and emits an Ed25519-signed, hash-chained receipt.
//
//	tessera --pack packs/mosa --manifest m.yaml --out receipt.json
//
// The engine knows nothing about any specific domain. MOSA is just the first
// pack; cyber/RMF is a second. A pack is described by a pack.yaml:
//
//	pack:    mosa
//	title:   Modular Open Systems Approach (MOSA)
//	version: "0.1"
//	query:   data.mosa.result   # the Rego entrypoint to evaluate
//	rules:   rules              # dir of .rego (relative to the pack)
//	library: library            # dir of *.yaml injected at data.library
//	schema:  schema/manifest.schema.json
//
// Exit codes: 0 = pass, 2 = deny (gate fails), 1 = error.
//
// LIMITATION (read docs/VIABILITY.md): the manifest is self-declared. A receipt
// attests that "the program ASSERTED X and X passes the rules" — not that the
// assertion matches the real system. Deriving manifests from real models/builds
// (the adapter roadmap) is what turns attestation into verification.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"sigs.k8s.io/yaml"
)

const toolVersion = "0.2.0-rough"

// packDescriptor is the pack.yaml contract.
type packDescriptor struct {
	Pack    string `json:"pack"`
	Title   string `json:"title"`
	Version string `json:"version"`
	Query   string `json:"query"`
	Rules   string `json:"rules"`
	Library string `json:"library"`
	Schema  string `json:"schema"`
}

type receipt struct {
	Tool        string         `json:"tool"`
	ToolVersion string         `json:"toolVersion"`
	Pack        string         `json:"pack"`
	PackTitle   string         `json:"packTitle"`
	PackVersion string         `json:"packVersion"`
	Manifest    string         `json:"manifest"`
	SignedAt    string         `json:"signedAt"`
	Report      map[string]any `json:"report"`
	Digest      string         `json:"digest"`     // sha256 hex of canonical report
	PrevDigest  string         `json:"prevDigest"` // previous receipt digest (chain)
	PublicKey   string         `json:"publicKey"`  // base64 ed25519 public key
	Signature   string         `json:"signature"`  // base64 ed25519 sig over digest bytes
}

func main() {
	var packDir, manifestPath, outPath, keyPath string
	flag.StringVar(&packDir, "pack", "", "path to a pack directory (containing pack.yaml)")
	flag.StringVar(&manifestPath, "manifest", "", "path to the manifest to check (yaml/json), or - for stdin")
	flag.StringVar(&outPath, "out", "", "path to write the signed receipt (optional)")
	flag.StringVar(&keyPath, "key", "tessera-ed25519.key", "ed25519 private key file (generated if absent)")
	flag.Parse()

	if packDir == "" || manifestPath == "" {
		fail("--pack and --manifest are required")
	}

	pack, err := loadPack(packDir)
	if err != nil {
		fail("loading pack: %v", err)
	}
	rulesDir := filepath.Join(packDir, pack.Rules)
	libDir := filepath.Join(packDir, pack.Library)

	input, err := loadManifest(manifestPath)
	if err != nil {
		fail("loading manifest: %v", err)
	}
	manifestName := "stdin"
	if manifestPath != "-" {
		manifestName = filepath.Base(manifestPath)
	}
	lib, err := mergeLibrary(libDir)
	if err != nil {
		fail("loading library: %v", err)
	}

	report, err := evaluate(context.Background(), rulesDir, pack.Query, lib, input)
	if err != nil {
		fail("evaluating rules: %v", err)
	}

	// Build the signed receipt over a canonical (sorted-key) report.
	canonical, _ := json.Marshal(report)
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])

	priv, err := loadOrCreateKey(keyPath)
	if err != nil {
		fail("key: %v", err)
	}
	sig := ed25519.Sign(priv, sum[:])

	rec := receipt{
		Tool:        "tessera",
		ToolVersion: toolVersion,
		Pack:        pack.Pack,
		PackTitle:   pack.Title,
		PackVersion: pack.Version,
		Manifest:    manifestName,
		SignedAt:    time.Now().UTC().Format(time.RFC3339),
		Report:      report,
		Digest:      digest,
		PrevDigest:  readPrev(outPath),
		PublicKey:   base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		Signature:   base64.StdEncoding.EncodeToString(sig),
	}

	recBytes, _ := json.MarshalIndent(rec, "", "  ")
	if outPath != "" {
		if err := os.WriteFile(outPath, recBytes, 0o644); err != nil {
			fail("writing receipt: %v", err)
		}
		writePrev(outPath, digest)
	}

	printSummary(pack, report)
	if outPath == "" {
		fmt.Println(string(recBytes))
	} else {
		fmt.Fprintf(os.Stderr, "receipt: %s (digest %s)\n", outPath, digest[:12])
	}

	if pass, _ := report["pass"].(bool); !pass {
		os.Exit(2)
	}
}

func loadPack(dir string) (*packDescriptor, error) {
	b, err := os.ReadFile(filepath.Join(dir, "pack.yaml"))
	if err != nil {
		return nil, err
	}
	var p packDescriptor
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.Query == "" {
		return nil, fmt.Errorf("pack.yaml must set `query` (the Rego entrypoint, e.g. data.mosa.result)")
	}
	if p.Rules == "" {
		p.Rules = "rules"
	}
	if p.Library == "" {
		p.Library = "library"
	}
	return &p, nil
}

// evaluate compiles the pack's rules with its library injected at data.library
// and the manifest as input, returning the pack's query result. Rules are loaded
// as modules (not via rego.Load) so the injected store stays read-only at eval.
func evaluate(ctx context.Context, rulesDir, query string, lib, input map[string]any) (map[string]any, error) {
	store := inmem.NewFromObject(map[string]any{"library": lib})
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Store(store),
		rego.Input(input),
	}
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") || strings.HasSuffix(e.Name(), "_test.rego") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Join(rulesDir, e.Name()))
		if rerr != nil {
			return nil, rerr
		}
		opts = append(opts, rego.Module(e.Name(), string(src)))
	}

	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("query %q produced no result (is the pack's `result` rule defined?)", query)
	}
	out, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T from %q", rs[0].Expressions[0].Value, query)
	}
	return out, nil
}

// mergeLibrary reads every *.yaml in dir and merges top-level keys into one map.
func mergeLibrary(dir string) (map[string]any, error) {
	merged := map[string]any{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		m, err := loadYAMLMap(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for k, v := range m {
			merged[k] = v // later files win on collision (only "version" collides)
		}
	}
	return merged, nil
}

func loadYAMLMap(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return unmarshalYAMLMap(b)
}

// loadManifest reads the manifest from a file, or from stdin when path is "-".
// This lets an adapter pipe a derived manifest straight in:
//
//	python sysml2bom.py model.sysml | tessera --pack packs/mosa --manifest -
func loadManifest(path string) (map[string]any, error) {
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return unmarshalYAMLMap(b)
	}
	return loadYAMLMap(path)
}

func unmarshalYAMLMap(b []byte) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil { // YAML (and JSON) -> JSON-compatible types
		return nil, err
	}
	return m, nil
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(b), nil
		}
		if dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); derr == nil && len(dec) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(dec), nil
		}
		return nil, fmt.Errorf("key file %s has unexpected size", path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if werr := os.WriteFile(path, priv, 0o600); werr != nil {
		return nil, werr
	}
	_ = os.WriteFile(path+".pub", priv.Public().(ed25519.PublicKey), 0o644)
	fmt.Fprintf(os.Stderr, "generated signing key: %s (.pub alongside)\n", path)
	return priv, nil
}

func chainPath(out string) string { return out + ".chain" }

func readPrev(out string) string {
	if out == "" {
		return ""
	}
	b, err := os.ReadFile(chainPath(out))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writePrev(out, digest string) {
	if out == "" {
		return
	}
	_ = os.WriteFile(chainPath(out), []byte(digest+"\n"), 0o644)
}

func printSummary(pack *packDescriptor, report map[string]any) {
	pass, _ := report["pass"].(bool)
	status := "PASS"
	if !pass {
		status = "FAIL"
	}
	fmt.Fprintf(os.Stderr, "[%s] %s: %s\n", pack.Pack, pack.Title, status)
	if m, ok := report["metrics"].(map[string]any); ok {
		parts := make([]string, 0, len(m))
		for k, v := range m {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		fmt.Fprintf(os.Stderr, "  metrics: %s\n", strings.Join(parts, " "))
	}
	printFindings("DENY", report["deny"])
	printFindings("WARN", report["warn"])
}

func printFindings(label string, v any) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	for _, item := range arr {
		f, _ := item.(map[string]any)
		fmt.Fprintf(os.Stderr, "  [%s] %s (%s): %s\n", label, f["code"], f["subject"], f["msg"])
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
