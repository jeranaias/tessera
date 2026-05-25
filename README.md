# Tessera

[![CI](https://github.com/jeranaias/tessera/actions/workflows/ci.yml/badge.svg)](https://github.com/jeranaias/tessera/actions/workflows/ci.yml)
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

# check the MOSA pack and write a signed receipt
./tessera.exe check --pack packs/mosa \
  --manifest packs/mosa/examples/example-radio/manifest.yaml --out receipt.json

# independently verify that receipt (signature + digest + optional chain)
./tessera.exe verify receipt.json

# the SAME binary, a different pack — no engine code changed
./tessera.exe check --pack packs/cyber-rmf \
  --manifest packs/cyber-rmf/examples/example-system/manifest.yaml
```

Other commands: `tessera packs` lists available packs, `tessera version` prints
the version. Prebuilt binaries are attached to each
[release](https://github.com/jeranaias/tessera/releases).

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
That makes today's output **attestation, not verification.** Closing that gap means
deriving the manifest from the actual model or build — which the **first adapter
now does** (see below). See [`docs/VIABILITY.md`](docs/VIABILITY.md) for the full,
unsparing assessment, the GAO context, and the existing-tooling landscape.

## From declared to derived (the adapter)

A hand-written manifest can lie; a manifest **derived from the model** cannot lie
about what the model says. [`adapters/sysmlv2/`](adapters/sysmlv2) reads a
**SysML v2** model and emits a MOSA-BOM, so the facts come from engineering, not
assertion:

```bash
# derive a manifest from a SysML v2 model, then gate it — one pipe
python adapters/sysmlv2/sysml2bom.py adapters/sysmlv2/examples/radio.sysml \
  | ./tessera.exe --pack packs/mosa --manifest -
```

The model marks the control↔crypto link as running on a proprietary bus, so the
*derived* manifest reflects that and the gate fails it — no one had to remember to
declare it. It's a documented SysML v2 *subset* parser (pure-Python, stdlib only,
air-gap friendly); objectives/requirements derivation and XMI/Capella adapters are
next. This is the single most important step toward real verification.

## Sign, verify, and waive

Every `check` emits a signed receipt; `verify` checks it independently — a
signature nobody can verify is theater:

```bash
./tessera.exe verify receipt.json                 # digest + signature + report verdict
./tessera.exe verify receipt.json --key <pubkey>  # REQUIRE a specific signer (pin trust)
./tessera.exe verify r1.json r2.json r3.json      # verify a CHAIN links cleanly over time
```

`verify` recomputes the report's digest, checks the Ed25519 signature, and (with
`--key`) refuses any receipt not signed by the key you trust. Tampering with the
report — e.g. flipping a `FAIL` to `PASS` — breaks the digest *and* the signature,
so `verify` exits non-zero.

**Waivers** honor MOSA's "to the maximum extent practicable." A non-severable
module or a proprietary key interface is sometimes legitimately justified (GFE
crypto, safety). A waiver doesn't hide the finding — it records it as `WAIVED`
with an **approver**, a **justification**, and an **expiry**, and lets the gate pass:

```bash
./tessera.exe check --pack packs/mosa \
  --manifest packs/mosa/examples/example-radio/manifest.yaml \
  --waivers  packs/mosa/examples/example-radio/waivers.yaml
# -> PASS, with [WAIVED] KEY_IFACE_NO_OPEN_STD recorded in the signed receipt
```

Expired waivers (`expires` < today) are ignored, so exceptions can't quietly
become permanent.

## What's in the box

```
tessera/
├── README.md                       ← you are here
├── AUTHORS.md                      ← concept & design credit (Tony Maida) + provenance
├── docs/VIABILITY.md               ← honest "is this viable?" assessment — read it
├── docs/CONOPS.md                  ← how a program uses it across a milestone + trust model
├── cmd/tessera/main.go             ← the engine (Go; embeds OPA; ~300 lines, domain-agnostic)
├── rulestest/                      ← `go test` harness that runs EVERY pack's rules
├── adapters/sysmlv2/               ← derive a manifest FROM a SysML v2 model (gap-closer)
├── .github/workflows/ci.yml        ← CI gate: build, test, both packs, adapter, end-to-end
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

Rough draft, but it runs and it's tested in CI. Real and working today:

- **engine** (`check` + `verify`), embedding OPA; one static binary
- **manifest schema validation** — malformed manifests are rejected with precise errors
- **signed receipts** + independent **verification** (digest, Ed25519 signature, key pinning, chain linkage)
- **signed, expiring, attributed waivers** ("to the maximum extent practicable")
- **SARIF output** (`--sarif`) — findings surface in GitHub code scanning / IDEs
- **stakeholder reports** (`tessera report --role peo|pm|engineer`) — role-tailored markdown from a receipt
- **cost/risk → value** — total cost, cost locked behind non-severable modules, high-risk advisories
- **MOSA pack** + **cyber-RMF** demonstration pack (multi-domain, content-only)
- **SysML v2 adapter** — derive a manifest from a model (attestation → verification)

**Deferred** (and named honestly in [`docs/VIABILITY.md`](docs/VIABILITY.md)):
deriving objectives/requirements in the adapter, UAF/SysML 1.x XMI + Capella
adapters, dashboards, and an optional cost-benefit module. The cyber-RMF pack is
a demonstration, not a production RMF tool.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Concept & design by **Tony Maida** — see [`AUTHORS.md`](AUTHORS.md).
