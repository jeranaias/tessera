// Command tessera is a domain-agnostic conformance engine with two subcommands:
//
//	tessera check  --pack packs/mosa --manifest m.yaml [--out receipt.json]
//	tessera verify receipt.json [--key <trusted-pubkey-b64>] [--prev <digest>]
//
// `check` evaluates a manifest against a pack (rules + library) and emits an
// Ed25519-signed, hash-chained receipt. `verify` independently checks that a
// receipt's report matches its signed digest, the signature verifies, and
// (optionally) that it was signed by a pinned key and links to a prior receipt.
// If no subcommand is given, `check` is assumed (back-compat).
//
// A pack is described by a pack.yaml (pack/title/version/query/rules/library).
//
// Exit codes: 0 = ok/pass, 2 = deny (check gate fails), 3 = invalid receipt
// (verify), 1 = error.
//
// LIMITATION (read docs/VIABILITY.md): a hand-written manifest is self-declared,
// so a receipt attests a CLAIM. Deriving manifests from real models (see
// adapters/) is what turns attestation into verification.
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
	"github.com/santhosh-tekuri/jsonschema/v5"
	"sigs.k8s.io/yaml"
)

const toolVersion = "0.3.0-rough"

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
	args := os.Args[1:]
	cmd := "check"
	if len(args) > 0 && (args[0] == "check" || args[0] == "verify") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "check":
		checkCmd(args)
	case "verify":
		verifyCmd(args)
	default:
		fail("unknown subcommand %q (want: check | verify)", cmd)
	}
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

func checkCmd(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var packDir, manifestPath, outPath, keyPath, waiversPath string
	fs.StringVar(&packDir, "pack", "", "path to a pack directory (containing pack.yaml)")
	fs.StringVar(&manifestPath, "manifest", "", "path to the manifest to check (yaml/json), or - for stdin")
	fs.StringVar(&waiversPath, "waivers", "", "optional waivers file (yaml/json) injected at data.waivers")
	fs.StringVar(&outPath, "out", "", "path to write the signed receipt (optional)")
	fs.StringVar(&keyPath, "key", "tessera-ed25519.key", "ed25519 private key file (generated if absent)")
	var noSchema bool
	fs.BoolVar(&noSchema, "no-schema", false, "skip manifest JSON Schema validation")
	_ = fs.Parse(args)

	if packDir == "" || manifestPath == "" {
		fail("check: --pack and --manifest are required")
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

	// Validate the manifest against the pack's JSON Schema (fail loudly on garbage).
	if !noSchema && pack.Schema != "" {
		schemaPath := filepath.Join(packDir, pack.Schema)
		if _, statErr := os.Stat(schemaPath); statErr == nil {
			if verr := validateManifest(schemaPath, input); verr != nil {
				fail("manifest does not satisfy %s:\n%v", pack.Schema, verr)
			}
		}
	}

	lib, err := mergeLibrary(libDir)
	if err != nil {
		fail("loading library: %v", err)
	}

	// Active (non-expired) waivers, injected at data.waivers for the rules.
	activeWaivers, err := loadActiveWaivers(waiversPath)
	if err != nil {
		fail("loading waivers: %v", err)
	}

	report, err := evaluate(context.Background(), rulesDir, pack.Query, lib, activeWaivers, input)
	if err != nil {
		fail("evaluating rules: %v", err)
	}

	digest, sig, priv, err := signReport(report, keyPath)
	if err != nil {
		fail("signing: %v", err)
	}

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

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var pinnedKey, expectedPrev string
	fs.StringVar(&pinnedKey, "key", "", "base64 ed25519 public key to REQUIRE (pins trust; otherwise the receipt's own embedded key is used)")
	fs.StringVar(&expectedPrev, "prev", "", "expected prevDigest, to enforce chain linkage")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		fail("usage: tessera verify <receipt.json|->")
	}

	var b []byte
	var err error
	if rest[0] == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(rest[0])
	}
	if err != nil {
		fail("reading receipt: %v", err)
	}

	var rec receipt
	if err := json.Unmarshal(b, &rec); err != nil {
		fail("parsing receipt: %v", err)
	}

	problems := verifyReceipt(&rec, pinnedKey, expectedPrev)
	if len(problems) == 0 {
		reportState := "FAIL"
		if p, _ := rec.Report["pass"].(bool); p {
			reportState = "PASS"
		}
		keyNote := "self-embedded key"
		if pinnedKey != "" {
			keyNote = "pinned key"
		}
		fmt.Fprintf(os.Stderr, "receipt VALID  pack=%s manifest=%q signed=%s (%s)\n",
			rec.Pack, rec.Manifest, rec.SignedAt, keyNote)
		fmt.Fprintf(os.Stderr, "  digest %s\n  underlying report: %s\n", rec.Digest, reportState)
		return
	}
	fmt.Fprintln(os.Stderr, "receipt INVALID:")
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "  - %s\n", p)
	}
	os.Exit(3)
}

// verifyReceipt returns a list of problems; empty means the receipt is valid.
func verifyReceipt(rec *receipt, pinnedKeyB64, expectedPrev string) []string {
	var problems []string

	canonical, err := canonicalJSON(rec.Report)
	if err != nil {
		return []string{fmt.Sprintf("cannot canonicalize report: %v", err)}
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != rec.Digest {
		problems = append(problems, "digest mismatch: report does not match the signed digest (report was altered)")
	}

	pub, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return append(problems, "invalid or missing public key")
	}
	sig, err := base64.StdEncoding.DecodeString(rec.Signature)
	if err != nil {
		return append(problems, "invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), sum[:], sig) {
		problems = append(problems, "signature does not verify against the embedded public key")
	}
	if pinnedKeyB64 != "" && pinnedKeyB64 != rec.PublicKey {
		problems = append(problems, "public key does not match the pinned --key (untrusted signer)")
	}
	if expectedPrev != "" && expectedPrev != rec.PrevDigest {
		problems = append(problems, fmt.Sprintf("prevDigest %q does not match expected --prev %q (broken chain)", rec.PrevDigest, expectedPrev))
	}
	return problems
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

// signReport canonicalizes the report, signs the SHA-256 of it, and returns the
// hex digest, signature bytes, and the private key used.
func signReport(report map[string]any, keyPath string) (string, []byte, ed25519.PrivateKey, error) {
	canonical, err := canonicalJSON(report)
	if err != nil {
		return "", nil, nil, err
	}
	sum := sha256.Sum256(canonical)
	priv, err := loadOrCreateKey(keyPath)
	if err != nil {
		return "", nil, nil, err
	}
	sig := ed25519.Sign(priv, sum[:])
	return hex.EncodeToString(sum[:]), sig, priv, nil
}

// canonicalJSON produces deterministic bytes (sorted keys, normalized number
// types) so that signing and verification agree regardless of how the report was
// constructed (OPA values vs. parsed-from-JSON values).
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var norm any
	if err := json.Unmarshal(b, &norm); err != nil {
		return nil, err
	}
	return json.Marshal(norm)
}

// ---------------------------------------------------------------------------
// pack + evaluation
// ---------------------------------------------------------------------------

// validateManifest checks the decoded manifest against the pack's JSON Schema.
func validateManifest(schemaPath string, input map[string]any) error {
	f, err := os.Open(schemaPath)
	if err != nil {
		return err
	}
	defer f.Close()

	c := jsonschema.NewCompiler()
	if err := c.AddResource("manifest.schema.json", f); err != nil {
		return err
	}
	sch, err := c.Compile("manifest.schema.json")
	if err != nil {
		return err
	}
	return sch.Validate(input)
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

// evaluate compiles the pack's rules with its library at data.library, active
// waivers at data.waivers, and the manifest as input, returning the pack's query
// result. Rules are loaded as modules (not via rego.Load) so the injected store
// stays read-only at eval.
func evaluate(ctx context.Context, rulesDir, query string, lib, waivers, input map[string]any) (map[string]any, error) {
	store := inmem.NewFromObject(map[string]any{"library": lib, "waivers": waivers["waivers"]})
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

// ---------------------------------------------------------------------------
// loaders
// ---------------------------------------------------------------------------

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

// loadActiveWaivers loads a waivers file and drops any whose `expires` date
// (YYYY-MM-DD) is in the past, so the rules only ever see *active* waivers.
// Returns {"waivers": [...]} (possibly empty).
func loadActiveWaivers(path string) (map[string]any, error) {
	if path == "" {
		return map[string]any{"waivers": []any{}}, nil
	}
	m, err := loadYAMLMap(path)
	if err != nil {
		return nil, err
	}
	raw, _ := m["waivers"].([]any)
	today := time.Now().UTC().Format("2006-01-02")
	active := make([]any, 0, len(raw))
	for _, w := range raw {
		wm, ok := w.(map[string]any)
		if !ok {
			continue
		}
		if exp, ok := wm["expires"].(string); ok && exp != "" && exp < today {
			continue // expired (string compare is valid for ISO YYYY-MM-DD)
		}
		active = append(active, wm)
	}
	return map[string]any{"waivers": active}, nil
}

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

func loadYAMLMap(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return unmarshalYAMLMap(b)
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

// ---------------------------------------------------------------------------
// receipt chain + output
// ---------------------------------------------------------------------------

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
	printFindings("WAIVED", report["waived"])
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
