# Contributing

This project is **content first**. Most contributions are not code — they are
new library entries and new rules. That is the whole point: it stays alive
because keeping it current is cheap.

## The three things you'll usually change

| You want to… | Edit | No code needed? |
|---|---|---|
| Add/retire an open standard | `library/standards.yaml` | ✅ |
| Add a MOSA objective or severability class | `library/objectives.yaml`, `library/severability.yaml` | ✅ |
| Add or change a conformance check | `rules/mosa.rego` (+ a test in `rules/mosa_test.rego`) | Rego only |
| Change the manifest contract | `schema/mosa-manifest.schema.json` | JSON Schema only |

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
# rules pack unit tests
go test ./...

# end-to-end smoke test against the worked example (expect FAIL + exit 2)
go build -o mosa-check.exe ./cmd/mosa-check
./mosa-check.exe --rules rules --library library --manifest examples/example-radio/manifest.yaml
```

## Attribution

The MOSA Domain Overlay concept is Tony Maida's (see `AUTHORS.md`). Please keep
that attribution intact in any fork or derivative.

By contributing you agree your contribution is licensed under Apache-2.0.
