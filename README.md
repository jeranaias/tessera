# MOSA Overlay

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status: rough draft](https://img.shields.io/badge/status-rough%20draft-orange.svg)](#status)
[![Built with Rego + Go](https://img.shields.io/badge/built%20with-Rego%20%2B%20Go-00ADD8.svg)](#whats-in-the-box)

**A checklist-as-code for building defense systems out of swappable parts — not a giant software platform.**

> **Concept & design: Tony Maida.** The *MOSA Domain Overlay* idea — a
> non-disruptive, model-based overlay for assessing and enforcing MOSA
> compliance across programs — is Tony Maida's. This repository is an
> open-source (Apache-2.0) implementation of that concept, deliberately reduced
> to its most sustainable form. See [`AUTHORS.md`](AUTHORS.md).

---

## What is this, in plain English?

When the U.S. military buys a big system — a radio, a drone, a vehicle — the law
(**MOSA**, *Modular Open Systems Approach*, [10 U.S.C. § 4401](https://www.law.cornell.edu/uscode/text/10/4401))
says it should be built like **LEGO, not like a welded sculpture**: made of
parts you can swap out, re-compete, and upgrade — instead of being locked to one
vendor forever.

The hard question is: *how do you actually check that a program followed the
rules?* Today that check is slow, manual, and inconsistent.

**This project is the check.** A program writes a short "parts list" describing
its building blocks and how they connect. You run one small program against it,
and you get back a **signed pass/fail report** — like a nutrition label or a
TSA checklist, but for "is this system actually modular and open?"

That's it. No portal to log into. No central database. No team to keep a website
running. Just a file, a checker, and a receipt you can hand to an auditor.

## Why not just build a big platform?

Most "enforce MOSA at scale" efforts try to build a central system: import
everyone's engineering models, run dashboards, host a portal. **Those die.** Not
because the idea is bad — because someone has to *fund, police, and operate* them
forever across hundreds of programs, and that money and attention never lasts.

Everything that actually *worked* in nearby fields did the opposite — it shipped
**content, not a platform**:

| What survived | What it really is |
|---|---|
| Security checklists (STIGs / CIS Benchmarks) | A list of rules in files |
| Software "ingredient labels" (SBOM) | A small *manifest*, not a central data lake |
| Code scanners (Semgrep, Trivy) | Ship the rules; run them in whatever you already have |

So this project is **a rules pack + a small manifest**, nothing more:

- **Police it** → a program milestone simply *requires a signed, passing receipt.* Yes/no. Like requiring an ingredient label.
- **Fund it** → a small group keeps the rules and the list of approved standards current (the STIG model). A git repo. No hosting, no servers.
- **Keep it rolling** → new open standard? Add one line. New policy? Add one rule. It's pull requests, forever cheap.

## How it works

```
   Your engineering model                    This repo
   (UAF / SysML / docs)                  ┌─────────────────────┐
            │                            │  library/  (data)   │  approved open standards,
            │  you summarize the         │  rules/    (Rego)   │  MOSA objectives, taxonomy
            │  relevant facts            └─────────┬───────────┘
            ▼                                      │
   ┌──────────────────┐      mosa-check      ┌─────▼───────────┐      ┌──────────────────┐
   │  MOSA-BOM         │ ───────────────────▶│   rules engine   │────▶ │  signed receipt   │
   │  (a small file)   │                     │   (OPA, embedded)│      │  pass / fail +    │
   └──────────────────┘                      └──────────────────┘      │  metrics + sig    │
   the program's OWN sidecar                                            └──────────────────┘
   — references the model,                                              feed it to a CI gate
     never changes it
```

The **MOSA-BOM** ("MOSA Bill of Materials") is the key idea borrowed from SBOM:
instead of forcing every program to dump its full engineering model into a
central system, each program emits a *tiny* file listing only the facts the rules
need. It's the program's own file. Add it → the MOSA view exists. Delete it →
nothing breaks. That is what "non-disruptive overlay" means, made concrete.

## Try it in 30 seconds

```bash
# build the checker (one static binary; first build downloads dependencies)
go build -o mosa-check.exe ./cmd/mosa-check

# check the worked example and write a signed receipt
./mosa-check.exe \
  --rules    rules \
  --library  library \
  --manifest examples/example-radio/manifest.yaml \
  --out      receipt.json
```

Real output from the included example (an illustrative software-defined radio):

```
MOSA conformance: FAIL
  mosa_index=64 open_std_coverage=67% modularity=75% conformance=50%
  [DENY] KEY_IFACE_NO_OPEN_STD (IF-CTRL-CRYPTO): key interface "IF-CTRL-CRYPTO" references no open standard from the library
  [WARN] KEY_IFACE_UNDOCUMENTED (IF-CTRL-CRYPTO): key interface "IF-CTRL-CRYPTO" is not marked documented
  [WARN] MODULE_NON_SEVERABLE (M-CRYPTO): module "M-CRYPTO" is non-severable (vendor-lock / tech-refresh risk)
receipt: receipt.json (digest f4dae7e6...)
```

**What that means in English:** the example radio is *mostly* good (modular, uses
open standards on most connections) but it **fails** because one important
connection — between the control app and the crypto box — runs over a *proprietary*
bus instead of an open standard. That's exactly the kind of vendor lock-in MOSA
exists to prevent, so the gate stops it. Exit code `2` means "do not pass the
milestone until this is fixed."

The `receipt.json` carries the score, every finding, and an **Ed25519 digital
signature** plus the previous receipt's fingerprint — so a program's receipts
form a tamper-evident chain an auditor can trust. It all runs offline, so it
works on an air-gapped network.

## A quick glossary (no jargon left behind)

| Term | Plain meaning |
|---|---|
| **MOSA** | The rule that defense systems should be modular and open, not locked to one vendor. |
| **Module** | A building block of the system (the RF unit, the waveform processor, …). |
| **Severable** | "Swappable" — can you replace this block without re-engineering everything around it? |
| **Key interface** | An important connection between blocks — the kind that decides whether you're locked in. |
| **Open standard** | A publicly maintained, vendor-neutral spec for a connection (e.g. FACE, SOSA, CMOSS). |
| **MOSA-BOM** | The small "parts list" file a program writes for this tool to check. |
| **Receipt** | The signed pass/fail report this tool produces. |

## What's in the box

```
mosa-overlay/
├── README.md                          ← you are here
├── AUTHORS.md                         ← concept & design credit (Tony Maida)
├── schema/mosa-manifest.schema.json   ← the MOSA-BOM "parts list" contract
├── library/                           ← the reusable content (the part that scales)
│   ├── standards.yaml                 ←   approved open standards (FACE/SOSA/CMOSS/…)
│   ├── objectives.yaml                ←   the MOSA goals (10 U.S.C. 4401)
│   └── severability.yaml              ←   the "how swappable" categories
├── rules/                             ← the checklist itself
│   ├── mosa.rego                      ←   the conformance rules
│   └── mosa_test.rego                 ←   unit tests for the rules
├── examples/example-radio/manifest.yaml   ← a worked, runnable MOSA-BOM
├── cmd/mosa-check/                    ← the checker (Go; embeds the rules engine)
└── rulestest/                         ← `go test` harness for the rules
```

## You don't have to do the heavy stuff (progressive disclosure)

A program can start tiny and add more only if it wants to:

- **Minimal** *(almost everyone)* — list your modules, your key interfaces, which
  standard each uses, and trace your objectives. Enough to pass or fail the gate.
- **Extended** *(optional)* — also attach cost ranges and risk-register entries,
  and value-scoring rules light up for portfolio rollups.

Tools that auto-generate a MOSA-BOM from an existing engineering model
(UAF/SysML/Capella exports) are a *later, optional plugin* — never a prerequisite.

## Where this came from (Tony Maida's design) and what we kept

Tony Maida's original MOSA Domain Overlay is a fuller, model-based framework with
five elements. This implementation maps them as follows — and is honest about
what it deliberately *deferred* to stay sustainable:

| Tony Maida's design element | In this repo |
|---|---|
| 1. Non-disruptive overlay | ✅ The MOSA-BOM is the program's own sidecar file; the model is never touched. |
| 2. Reusable libraries + validation rules | ✅ **This is the core.** `library/` + `rules/`. |
| 3. Lightweight ontology (UAF-based) | ◐ Shrunk to *just enough* schema to make rules unambiguous (`schema/`). |
| 4. Normalize diverse artifacts + value algorithms | ◐ Optional **Extended** manifest tier instead of a mandatory central pipeline. |
| 5. Guided workflows + role dashboards | ○ Deferred. A thin renderer over receipts is a later add-on, not the product. |

The reduction is the strategy: keep the parts that scale on their own; make the
expensive parts optional. The foundational concept remains Tony Maida's.

## Status

Rough draft, but it runs. The schema, the open-standards library, the rules pack,
the worked example, and the signing CLI are real and tested (`go test ./...`
passes; the example produces a signed receipt). Model-import adapters and
dashboards are intentionally out of scope for now.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Concept & design by **Tony Maida** — see [`AUTHORS.md`](AUTHORS.md).
