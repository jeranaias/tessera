# cyber-rmf pack — DEMONSTRATION ONLY

> ⚠️ **This pack exists to prove one thing: the `tessera` engine is
> domain-agnostic.** It is the *same* engine, the *same* manifest + rules +
> signed-receipt pattern as the MOSA pack — pointed at a completely different
> concern (NIST SP 800-53 / RMF control coverage).
>
> **It is not a production RMF, eMASS, or ATO tool.** It checks a hand-written
> 5-control subset with a handful of rules. Do not use it for real
> authorization decisions. A real pack would import the OSCAL catalog and
> profiles and model assessment evidence properly.

## What it shows

Run the same binary, just a different `--pack`:

```bash
tessera --pack packs/cyber-rmf --manifest packs/cyber-rmf/examples/example-system/manifest.yaml
```

Expected (the example is seeded to fail):

```
[cyber-rmf] Cyber / RMF control coverage (DEMONSTRATION): FAIL
  metrics: baseline=moderate baseline_controls=5 implemented_pct=60 ...
  [DENY] NOT_IMPLEMENTED_NO_POAM (SC-7): baseline control "SC-7" is not-implemented with no POA&M
  [WARN] PLANNED_NO_DATE (AU-2): planned control "AU-2" has no target date
```

The point: **no engine code changed** to support cyber/RMF. Only `pack.yaml`,
`library/controls.yaml`, and `rules/rmf.rego` are new — all content, no platform.
That is the whole thesis of the project, demonstrated across two domains.
