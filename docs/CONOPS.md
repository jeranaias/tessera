# Concept of Operations

How a program actually uses Tessera across its lifecycle — and the trust model
that makes the output meaningful. (For the candid limits, read
[`VIABILITY.md`](VIABILITY.md).)

## The actors

- **Program / contractor** — produces the system and its model; emits the
  manifest (by hand, or *derived* from the model via an adapter).
- **Authorizing Official (AO) / lead engineer** — owns policy: approves waivers,
  holds the signing key, and is accountable for the verdict.
- **Milestone reviewer / auditor** — consumes a signed receipt and verifies it;
  never has to re-run the toolchain or trust the program's word.

## The loop

```
   author or DERIVE a manifest            run the gate (CI or milestone)
   ┌──────────────────────┐               ┌───────────────────────────┐
   │  model ──adapter──▶   │               │  tessera check --pack ...  │
   │  MOSA-BOM manifest    │ ────────────▶ │   [+ --waivers from AO]    │ ──▶ signed receipt.json
   └──────────────────────┘               └───────────────────────────┘            │
                                                                                     ▼
   milestone review / audit                                          tessera verify receipt.json
   ┌──────────────────────┐                                          ┌───────────────────────────┐
   │ reviewer pins the AO  │ ◀──────────────────────────────────────│ digest + signature + chain │
   │ key, verifies receipt │                                          └───────────────────────────┘
   └──────────────────────┘
```

1. **Author / derive.** The program writes a MOSA-BOM, or — better — derives it
   from the engineering model with an adapter (`adapters/sysmlv2/`). Deriving is
   what makes the result *verification* rather than *attestation*: the facts come
   from the model, not a claim.
2. **Gate.** `tessera check` runs in the program's CI on every change and/or at a
   milestone. Exit `2` blocks the gate; the build is red until findings are fixed
   or waived. Manifests are schema-validated first, so malformed input fails loudly.
3. **Waive (when justified).** Some findings are legitimate ("to the maximum
   extent practicable" — GFE crypto, safety). The AO issues a **waiver**: a
   signed, attributed, **expiring** exception. The finding is recorded as `WAIVED`
   in the receipt — never hidden. Expired waivers stop applying automatically.
4. **Sign.** Every `check` emits an Ed25519-signed receipt carrying the metrics,
   every finding (deny / waived / warn), a digest of the report, and the previous
   receipt's digest — so a program's receipts form a tamper-evident **chain**.
5. **Verify.** At the milestone review, the reviewer runs `tessera verify
   --key <AO-public-key> receipt.json`. This confirms the report wasn't altered,
   the signature is valid, and it was signed by the **trusted** key — without
   re-running anything or trusting the program.

## Trust model (read this)

- A receipt proves **integrity + provenance**: "this exact report was signed by
  this key and hasn't changed." It does **not** prove the *manifest matched
  reality* unless the manifest was **derived from the model/build**. Derivation is
  the load-bearing step; hand-written manifests are attestations of a claim.
- **Pin the key.** `verify` without `--key` only checks internal consistency
  (the receipt's own embedded key). Real assurance requires pinning the AO's
  public key with `--key`, so a receipt signed by anyone else is rejected.
- **Key custody is the program's responsibility.** The AO (or a program signing
  service / HSM) holds the private key. Tessera generates a dev key if none
  exists — fine for local use, not for authority.

## How it scales without a platform

There is no server to operate. The rules pack and library are versioned content
in git (the STIG / CIS model); each program runs the one static binary in its own
CI; receipts live with the program's records. A new compliance domain is a new
`packs/<name>/` folder — no engine change. That is the whole point: police it by
requiring a signed, verifiable receipt at the gate; fund it as content
maintenance; keep it rolling with pull requests.

## Milestone integration sketch

- **CI gate:** add `tessera check` to the pipeline (see `.github/workflows/ci.yml`
  for a working example). Block merges on exit `2`.
- **Milestone artifact:** attach `receipt.json` (and the waiver file, if any) to
  the milestone package. The reviewer verifies it with the pinned AO key.
- **Over time:** keep receipts; `--prev` links each to the last, so the chain
  shows the program's conformance history wasn't rewritten.
