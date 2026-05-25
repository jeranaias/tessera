# Viability assessment — read this before believing the README

This document is deliberately critical. A federal audience trusts a tool that is
honest about its limits more than one that oversells. Here is the straight
assessment of what this project is, what it is not, and what would make it real.

## BLUF

- **This is not "the answer to MOSA," and it should not be pitched as one.**
  MOSA's binding constraints are economic, contractual, and engineering problems
  that no conformance checker can solve.
- **It is a viable, narrow component**: an automatable, signed
  *verification-and-attestation gate*. That maps onto a real, GAO-documented gap.
- **The engine is domain-agnostic.** MOSA is the flagship pack; the cyber/RMF
  pack proves the same engine serves other compliance concerns with content
  only. The reusable engine — not the MOSA pack — is the most durable asset here.

## What MOSA actually requires

MOSA ([10 U.S.C. § 4401](https://www.law.cornell.edu/uscode/text/10/4401)) is an
*integrated business **and** technical strategy*, required "to the maximum extent
practicable." Two consequences matter for tooling:

1. The hard part is upstream **acquisition strategy** — RFP language, **data
   rights**, contract structure, incentives — not the architecture diagram.
2. "To the maximum extent practicable" means MOSA is **judgment-laden and
   waiverable**, not a binary spec. A pure pass/fail gate misframes it without a
   structured exception path.

## The real bottlenecks (per GAO, not us)

[GAO-25-106931 (Jan 2025)](https://www.gao.gov/products/gao-25-106931) reviewed
20 programs and made **14 recommendations**. The gaps:

| GAO finding | Does this tool help? |
|---|---|
| **#1 — no cost-benefit method** (none of 20 programs did one; policy doesn't require it) | **No.** This checks structural conformance, not economics. |
| Programs don't plan to **verify** MOSA implementation before production | **Yes** — this is a verification gate. |
| Programs don't **document** key MOSA planning elements in acquisition docs | **Yes** — a manifest can enforce completeness. |
| Policy gaps (middle-tier pathway), cybersecurity planning | Partially / no. |

And the deepest barrier isn't a tooling problem at all: **intellectual property
and data rights.** If the government doesn't buy rights to the interfaces,
modularity is theoretical regardless of the architecture
([govmates](https://govmates.com/mosa-and-ip-key-legal-considerations-for-contractors/),
[Breaking Defense / FLRAA](https://breakingdefense.com/2025/01/addressing-risk-and-intellectual-property-rights-in-the-flraa-supply-chain/)).
A rules pack cannot acquire data rights or change vendor incentives.

**Net:** of the things blocking MOSA — cost-benefit justification, IP/data
rights, incentives, and the engineering itself — this tool addresses none of the
hard ones. It addresses verification-and-documentation, which is real but
secondary.

## The niche is not empty

- The **MOSA Implementation Guidebook (Feb 2025)** ships an **Appendix B on MOSA
  Assessment Tools** ([cto.mil](https://www.cto.mil/wp-content/uploads/2025/03/MOSA-Implementation-Guidebook-27Feb2025-Cleared.pdf)).
- The **OA PNT tool** is an Excel **Criteria Scoring Matrix** already used for MOSA assessment.
- The **FACE Conformance Test Suite** is a free, government-recognized program that
  tests software against the FACE standard — real verification, not self-report
  ([The Open Group](https://www.opengroup.org/The-Open-Group-SOSA-and-FACE-Consortia-Applaud-New-Tri-Services-Directive-Memorandum-that-Furthers-the-DOD's-Modular-Open-Systems-Commitment)).
- OUSD(R&E) maintains a [Review of MOSA Tools and Practices (2022)](https://www.cto.mil/wp-content/uploads/2023/06/MOSA-Tools-2022.pdf).

**Differentiator (honest):** existing tools are either subjective Excel matrices
(manual, not gateable in CI, not signed) or deep but standard-specific (FACE CTS
= FACE avionics software only). Nothing in that landscape is a lightweight,
cross-standard, automatable, **signed**, air-gapped, open-source gate. That gap
is real — but "differentiated component" ≠ "the answer."

## The limitation that decides everything: attestation ≠ verification

The manifest is **self-declared by the program.** A signed receipt proves "the
program *asserted* X, and X passes the rules." It does **not** prove the
assertion matches the real system. A program can mislabel a non-severable module
"severable," or claim FACE conformance it doesn't have, and the tool signs it
green.

Compare the models this project is built on:

- **SBOM** is increasingly **machine-generated from the build** (provenance).
- **STIG/SCAP** checks scan the **actual system**.

Their credibility comes from being derived from ground truth. The analog here —
auto-generating the manifest from the real UAF/SysML model or the build — is
precisely the adapter work that is **deferred**. So today the trust model is
weaker than its role models, and the fix lives in the unbuilt part. This is the
single most important caveat.

## Other known gaps

- **No waiver/justification path.** "Maximum extent practicable" means
  non-severable modules are often legitimately justified (crypto, safety). A gate
  without first-class signed waivers will be ignored by PMs. (`warn` is a start.)
- **Composite indices are gameable.** A single "MOSA index" invites checkbox
  compliance — the exact failure mode MOSA already suffers.

## Provenance note (attribution precision)

This repo attributes the **MOSA Domain Overlay concept** to **Tony Maida**. For
accuracy: the general UAF "Domain Overlay" *construct* has prior public authorship
— see Shearin & Wise (Georgia Tech Research Institute), OMG, March 2023,
*"How I Stumbled Across A Domain Overlay and Why It's Actually Useful"*
([OMG PDF](https://www.omg.org/uaf/resources/march-2023/How-I-Stumbled-Across-A-Domain-Overlay-and-Why-It-Actually-Useful-Shearin-Wise-Georgia-Tech-Research-Institute.pdf)).
The cleanest framing is "MOSA Domain Overlay design by Tony Maida, building on the
UAF domain-overlay construct." See [`../AUTHORS.md`](../AUTHORS.md).

## Verdict

| Question | Answer |
|---|---|
| Is this "the answer to MOSA"? | **No.** Doesn't touch cost-benefit, IP/data rights, incentives, or the engineering. |
| Is it a viable, valuable component? | **Yes** — a signed verification/attestation + planning-completeness gate (GAO gaps). |
| Is the niche defensible? | **Partly.** Differentiated (automatable/signed/cross-standard/open) but not empty. |
| What's the make-or-break? | The **adapters**: until the manifest is *derived*, you sign claims, not reality. **First cut shipped** (SysML v2); see roadmap. |
| Why generalize the engine? | The reusable signed-conformance engine outlives any single domain; MOSA is the lighthouse. |

## Roadmap to actual viability

1. ✅ **First model-import adapter (shipped):** [`adapters/sysmlv2/`](../adapters/sysmlv2)
   derives a MOSA-BOM from a **SysML v2** model, so the manifest is **derived, not
   declared** — the start of attestation → verification. Documented subset; next:
   derive objectives/requirements, and add UAF/SysML 1.x XMI + Capella adapters.
2. ✅ **CI gate (shipped):** `.github/workflows/ci.yml` builds, tests every pack,
   gates both examples, runs the adapter, runs the end-to-end derive→gate pipe,
   signs a receipt + verifies it, exercises the waiver flow, and rejects a
   tampered receipt.
3. ✅ **Receipt verification (shipped):** `tessera verify` independently checks a
   receipt's digest + Ed25519 signature, can **pin a trusted signer** (`--key`),
   and can enforce chain linkage (`--prev`). A signed artifact nobody can verify
   is theater; now it isn't.
4. ✅ **Signed, justified waivers (shipped):** `--waivers` lets a justified,
   attributed, **expiring** exception pass the gate while recording it as
   `WAIVED` — honoring "to the maximum extent practicable" without hiding it.
5. **Derive objectives/requirements** in the adapter; add UAF/SysML 1.x XMI +
   Capella adapters; harden the cyber-rmf rules like MOSA's.
6. *(Optional, later)* a cost-benefit module to chase GAO Recommendation #1.

## Sources

- [10 U.S.C. § 4401](https://www.law.cornell.edu/uscode/text/10/4401)
- [GAO-25-106931](https://www.gao.gov/products/gao-25-106931)
- [OUSD(R&E) MOSA](https://www.cto.mil/sea/mosa/) · [MOSA Implementation Guidebook (Feb 2025)](https://www.cto.mil/wp-content/uploads/2025/03/MOSA-Implementation-Guidebook-27Feb2025-Cleared.pdf) · [MOSA Tools Review (2022)](https://www.cto.mil/wp-content/uploads/2023/06/MOSA-Tools-2022.pdf)
- [The Open Group SOSA/FACE on the Tri-Service memo](https://www.opengroup.org/The-Open-Group-SOSA-and-FACE-Consortia-Applaud-New-Tri-Services-Directive-Memorandum-that-Furthers-the-DOD's-Modular-Open-Systems-Commitment)
- [MOSA & IP / data rights](https://govmates.com/mosa-and-ip-key-legal-considerations-for-contractors/) · [FLRAA IP](https://breakingdefense.com/2025/01/addressing-risk-and-intellectual-property-rights-in-the-flraa-supply-chain/)
- [OMG domain-overlay paper, Shearin & Wise, GTRI (Mar 2023)](https://www.omg.org/uaf/resources/march-2023/How-I-Stumbled-Across-A-Domain-Overlay-and-Why-It-Actually-Useful-Shearin-Wise-Georgia-Tech-Research-Institute.pdf)
