# Tessera

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status: rough draft](https://img.shields.io/badge/status-rough%20draft-orange.svg)](#status--honest-scope)
[![Built with Rego + Go](https://img.shields.io/badge/built%20with-Rego%20%2B%20Go-00ADD8.svg)](#whats-in-the-box)

**A domain-agnostic, signed conformance gate — checklist-as-code for cross-cutting
compliance concerns. MOSA is the first pack; it is not the only one.**

> *Tessera* — a single tile in a mosaic, and a Roman token of proof or
> authorization. Both meanings are the point: programs are assembled from
> **modular tiles**, and Tessera issues a **signed token** that says whether the
> assembly conforms.

> **Concept & design: Tony Maida**, building on the UAF "Domain Overlay" construct
> (see [`AUTHORS.md`](AUTHORS.md)). This repo is an open-source (Apache-2.0)
> implementation, reduced to its most sustainable form.
>
> 📋 **Read [`docs/VIABILITY.md`](docs/VIABILITY.md) first.** It says plainly what
> this is and is *not*. Short version: this is **not "the answer to MOSA"** — it's
> a narrow, useful *verification-and-attestation* layer. Honesty about scope is
> the point.

---

## What is this, in plain English?

A "Domain Overlay" is a cross-cutting check you can lay over a program — for
**MOSA**, **cybersecurity**, **nuclear surety**, or any compliance concern —
*without* touching the underlying system. You add it to get a verdict; you remove
it and nothing breaks.

Tessera makes that concrete and cheap:

1. A program writes a small **manifest** (a "parts list" / declaration of facts).
2. You run one binary against it with a chosen **pack** of rules.
3. You get a **signed pass/fail receipt** — like a nutrition label or a TSA
   checklist, but for "did this program actually follow the rules?"

No portal. No central database. No team keeping a website alive. Just a file, a
checker, and a receipt an auditor can verify. It runs offline (air-gap friendly).

## Why a pack engine, not a platform?

Efforts that try to *enforce compliance at scale* by building a central platform
(import everyone's models, run dashboards, host a portal) **die** — someone has
to fund, police, and operate them forever. Everything that actually scaled did
the opposite and shipped **content, not a platform**: security checklists
(STIGs/CIS), software ingredient labels (SBOM), code scanners (Semgrep/Trivy).

So Tessera is an **engine + packs**:

- The **engine** (`tessera`) is ~300 lines of Go. It knows nothing about any
  domain. It loads a pack, evaluates its rules against a manifest, and signs the
  result.
- A **pack** is pure content: a rules file (Rego), a reusable library (YAML), a
  manifest schema, and examples. Adding a domain = adding a folder. No new code.

This repo ships **two packs** to prove the point:

| Pack | What it checks | Status |
|---|---|---|
| [`packs/mosa`](packs/mosa) | Modular Open Systems Approach conformance | Flagship |
| [`packs/cyber-rmf`](packs/cyber-rmf) | NIST 800-53 / RMF control coverage | **Demonstration only** — proves the engine is domain-agnostic |

## How it works

```
   Your model / system                      A pack (pure content)
   (UAF / SysML / docs)                  ┌──────────────────────────┐
            │                            │  pack.yaml  (descriptor)  │
            │  you summarize the         │  library/   (data)        │
            │  relevant facts            │  rules/     (Rego)        │
            ▼                            └────────────┬─────────────┘
   ┌──────────────────┐      tessera            ┌─────▼───────────┐    ┌──────────────────┐
   │  manifest         │ ──────────────────────▶│  rules engine    │──▶ │  signed receipt   │
   │  (a small file)   │   --pack packs/mosa     │  (OPA, embedded) │    │  pass/fail +      │
   └──────────────────┘                         └──────────────────┘    │  metrics + sig    │
   the program's OWN sidecar                                             └──────────────────┘
   — references the model,                                               feed it to a CI gate
     never changes it
```

The manifest borrows the **SBOM** idea: instead of forcing programs to dump full
engineering models into a central system, each program emits a *tiny* file with
only the facts the rules need. It's the program's own file — add it and the
overlay view exists; delete it and nothing breaks. That is "non-disruptive
overlay," made concrete.

## Try it in 30 seconds

```bash
# build the engine (one static binary; first build downloads dependencies)
go build -o tessera.exe ./cmd/tessera

# MOSA pack
./tessera.exe --pack packs/mosa \
  --manifest packs/mosa/examples/example-radio/manifest.yaml --out receipt.json

# the SAME binary, a different pack — no engine code changed
./tessera.exe --pack packs/cyber-rmf \
  --manifest packs/cyber-rmf/examples/example-system/manifest.yaml
```

Real output from the MOSA example (an illustrative software-defined radio):

```
[mosa] Modular Open Systems Approach (MOSA): FAIL
  metrics: mosa_index=64 open_std_coverage_pct=67 modularity_score_pct=75 conformance_verified_pct=50 ...
  [DENY] KEY_IFACE_NO_OPEN_STD (IF-CTRL-CRYPTO): key interface "IF-CTRL-CRYPTO" references no open standard from the library
  [WARN] KEY_IFACE_UNDOCUMENTED (IF-CTRL-CRYPTO): key interface "IF-CTRL-CRYPTO" is not marked documented
  [WARN] MODULE_NON_SEVERABLE (M-CRYPTO): module "M-CRYPTO" is non-severable (vendor-lock / tech-refresh risk)
```

**In English:** the example radio is mostly good but **fails** because one
important connection (control app ↔ crypto box) runs over a *proprietary* bus
instead of an open standard — exactly the vendor lock-in MOSA exists to prevent.
Exit code `2` means "don't pass the milestone until this is fixed." The
`receipt.json` carries the score, every finding, an **Ed25519 signature**, and
the previous receipt's fingerprint, so receipts form a tamper-evident chain.

## The honest caveat (the one that matters)

The manifest is **self-declared**. A signed receipt proves "the program *asserted*
X and X passes the rules" — **not** that the assertion matches the real system.
That makes today's output **attestation, not verification.** Turning it into real
verification means deriving the manifest from the actual model or build (the
adapter roadmap). See [`docs/VIABILITY.md`](docs/VIABILITY.md) for the full,
unsparing assessment, the GAO context, and the existing-tooling landscape.

## What's in the box

```
tessera/
├── README.md                       ← you are here
├── AUTHORS.md                      ← concept & design credit (Tony Maida) + provenance
├── docs/VIABILITY.md               ← honest "is this viable?" assessment — read it
├── cmd/tessera/main.go             ← the engine (Go; embeds OPA; ~300 lines, domain-agnostic)
├── rulestest/                      ← `go test` harness that runs EVERY pack's rules
└── packs/
    ├── mosa/                       ← flagship pack
    │   ├── pack.yaml               ←   descriptor (rules dir, library dir, Rego query)
    │   ├── schema/manifest.schema.json
    │   ├── library/                ←   open-standards registry, MOSA objectives, severability
    │   ├── rules/                  ←   conformance rules (Rego) + unit tests
    │   └── examples/
    └── cyber-rmf/                  ← DEMONSTRATION pack (proves multi-domain)
        ├── pack.yaml
        ├── schema/  library/  rules/  examples/
        └── README.md               ←   "this is a stub, not a real RMF tool"
```

## Adding a new domain

No engine changes. Copy a pack folder, then edit three things:

1. `library/*.yaml` — your reference data (approved standards, control catalog, …)
2. `rules/*.rego` — your `deny` / `warn` rules and `result` (+ tests)
3. `pack.yaml` — point `query` at your Rego entrypoint (e.g. `data.yourpack.result`)

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Status / honest scope

Rough draft, but it runs. Real and tested (`go test ./...` passes; both packs
produce signed receipts): the engine, the MOSA pack, and the cyber-RMF
demonstration pack. **Deferred** (and load-bearing for real credibility):
model-import adapters that *derive* manifests, signed justified-waivers, and
dashboards. The cyber-RMF pack is explicitly a demonstration, not a production
RMF tool.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Concept & design by **Tony Maida** — see [`AUTHORS.md`](AUTHORS.md).
