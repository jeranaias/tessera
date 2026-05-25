# sysml2bom — SysML v2 → MOSA-BOM adapter

**This is the gap-closer.** Tessera's core limitation (see
[`../../docs/VIABILITY.md`](../../docs/VIABILITY.md)) is that a hand-written
manifest is *self-declared* — the signed receipt attests a **claim**, not the
**reality** of the system. This adapter derives the manifest from a **SysML v2
model**, so the facts come from engineering, not assertion.

> A program can hand-edit a YAML manifest to claim FACE conformance it doesn't
> have. It cannot make a manifest *derived from the model* lie about what the
> model says. That is the difference between **attestation** and **verification**.

## Use it

```bash
# derive a manifest from a model
python sysml2bom.py examples/radio.sysml -o radio-bom.json

# or pipe straight into the gate (Tessera reads "-" from stdin)
python sysml2bom.py examples/radio.sysml | \
  ../../tessera --pack ../../packs/mosa --manifest -
```

The included `examples/radio.sysml` derives to a manifest that **fails** the MOSA
gate, because the model itself shows a key interface (control ↔ crypto) running
on a proprietary bus.

## Supported subset (honest scope)

This is a **documented subset parser**, not a full SysML v2 implementation:

| Construct | Maps to |
|---|---|
| `@Program { id; name; milestone; }` (top-level) | `program` |
| `part <usage> [: Def] { @MOSA { severability; supplier; } }` | a `module` |
| `connection <n> [: Def] connect <a> to <b> { @MOSA { key; standards; documented; } }` | an `interface` |

Conventions:
- A `part` becomes a module only if its body has an `@MOSA` block with
  `severability` **before** any nested part/connection (so container parts aren't
  mistaken for modules).
- `standards = "A,B"` is split into a list.
- `//` and `/* */` comments are ignored.

**Not yet derived** (would still be self-declared if your rules need them):
objectives, requirements, cost, risk. Pure-Python, stdlib only (no pip install),
so it runs in an air-gapped environment.

## Tests

```bash
python test_sysml2bom.py        # stdlib only; also works under pytest
```

## Roadmap

- Derive objectives/requirements traceability from the model.
- Adapters for UAF/SysML 1.x XMI and Capella, and for build artifacts.
- A `--strict` mode that fails if the model is missing required `@MOSA` metadata.
