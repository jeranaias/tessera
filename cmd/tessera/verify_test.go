package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// signed builds a valid signed receipt for a given report and returns it plus
// the base64 public key that signed it.
func signed(t *testing.T, report map[string]any, prev string) (*receipt, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	return &receipt{
		Report:     report,
		Digest:     hex.EncodeToString(sum[:]),
		PrevDigest: prev,
		PublicKey:  pubB64,
		Signature:  base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sum[:])),
	}, pubB64
}

func TestVerifyValid(t *testing.T) {
	rec, pub := signed(t, map[string]any{"pass": true, "metrics": map[string]any{"mosa_index": 64}}, "")
	if p := verifyReceipt(rec, "", ""); len(p) != 0 {
		t.Fatalf("expected valid, got problems: %v", p)
	}
	// also valid when pinning the correct key
	if p := verifyReceipt(rec, pub, ""); len(p) != 0 {
		t.Fatalf("expected valid with correct pinned key, got: %v", p)
	}
}

func TestVerifyDetectsTamperedReport(t *testing.T) {
	rec, _ := signed(t, map[string]any{"pass": false}, "")
	rec.Report["pass"] = true // flip the verdict after signing
	p := verifyReceipt(rec, "", "")
	if len(p) == 0 {
		t.Fatal("expected tamper to be detected")
	}
}

func TestVerifyDetectsBadSignature(t *testing.T) {
	rec, _ := signed(t, map[string]any{"pass": true}, "")
	rec.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	p := verifyReceipt(rec, "", "")
	if len(p) == 0 {
		t.Fatal("expected bad signature to be detected")
	}
}

func TestVerifyPinnedKeyMismatch(t *testing.T) {
	rec, _ := signed(t, map[string]any{"pass": true}, "")
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	p := verifyReceipt(rec, base64.StdEncoding.EncodeToString(otherPub), "")
	if len(p) == 0 {
		t.Fatal("expected untrusted-signer detection when pinning a different key")
	}
}

func TestVerifyPrevChainMismatch(t *testing.T) {
	rec, _ := signed(t, map[string]any{"pass": true}, "abc123")
	if p := verifyReceipt(rec, "", "abc123"); len(p) != 0 {
		t.Fatalf("expected matching prev to pass, got: %v", p)
	}
	if p := verifyReceipt(rec, "", "deadbeef"); len(p) == 0 {
		t.Fatal("expected broken-chain detection")
	}
}
