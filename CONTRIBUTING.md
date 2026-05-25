# Contributing

This project is **content first**. Most contributions are not code — they are
new library entries and new rules. That is the whole point: it stays alive
because keeping it current is cheap.

## The three things you'll usually change

| You want to… | Edit | No code needed? |
|---|---|---|
| Add/retire an open standard (MOSA) | `packs/mosa/library/standards.yaml` | ✅ |
| Add a MOSA objective or severability class | `packs/mosa/library/objectives.yaml`, `…/severability.yaml` | ✅ |
| Add or change a conformance check | `packs/<pack>/rules/*.rego` (+ a test alongside) | Rego only |
| Change a manifest contract | `packs/<pack>/schema/manifest.schema.json` | JSON Schema only |
| **Add a whole new domain** | a new `packs/<pack>/` folder (see below) | content only |

## Adding a new pack (no engine code)

Copy an existing pack folder and change three things:

1. `library/*.yaml` — your reference data.
2. `rules/*.rego` — your `deny`/`warn` rules and a top-level `result` (+ tests). Use a unique package name, e.g. `package yourpack`.
3. `pack.yaml` — set `query: data.yourpack.result` and the `rules`/`library` dirs.

The `cyber-rmf` pack is a minimal worked example of exactly this.

## Rules

- Every new rule in `rules/mosa.rego` should ship with a test in
  `rules/mosa_test.rego`. Test helpers must **not** be named `test_*` (the OPA
  tester runs anything named `test_*` as a test case).
- Keep `deny` for things that should *fail a milestone gate* and `warn` for
  advisory findings. When in doubt, start as `warn`.
- Library entries should cite a steward/governing body so reviewers can verify
  the `open: true/false` call.

## Checks before you open a PR

```bash
# unit tests for EVERY pack's rules
go test ./...

# end-to-end smoke test against the worked examples (expect FAIL + exit 2)
go build -o tessera.exe ./cmd/tessera
./tessera.exe --pack packs/mosa      --manifest packs/mosa/examples/example-radio/manifest.yaml
./tessera.exe --pack packs/cyber-rmf --manifest packs/cyber-rmf/examples/example-system/manifest.yaml
```

## Attribution

The MOSA Domain Overlay concept is Tony Maida's (see `AUTHORS.md`). Please keep
that attribution intact in any fork or derivative.

By contributing you agree your contribution is licensed under Apache-2.0.
