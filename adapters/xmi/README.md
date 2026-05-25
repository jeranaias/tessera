# uml2bom — UML/SysML XMI → MOSA-BOM adapter

Derives a MOSA-BOM from a **real Papyrus/EMF XMI** model. The structural mapping
was reverse-engineered from genuine exports (the Papyrus **SimpleExcavator** and
**Airbag** SysML models), not guessed.

```bash
# real Papyrus SysML model -> manifest -> gate (it declares no MOSA attributes,
# so the gate correctly reports every block is missing severability)
python uml2bom.py examples/excavator.uml | \
  ../../tessera check --pack ../../packs/mosa --manifest -

# a faithfully-encoded model WITH @MOSA annotations -> full extraction
python uml2bom.py examples/radio-annotated.uml | \
  ../../tessera check --pack ../../packs/mosa --manifest -
```

## What it maps (validated against real models)

| XMI construct | MOSA-BOM |
|---|---|
| `<packagedElement xmi:type="uml:Class">` with a `<…:Block base_Class=…/>` stereotype | a `module` (falls back to all classes if no Block stereotypes) |
| `<packagedElement xmi:type="uml:Association">` between two distinct blocks | an `interface` (`between` resolved via memberEnd → Property `type`) |
| `<ownedComment annotatedElement="…">` whose body holds `@MOSA …` | MOSA attributes on the annotated module/interface |

`@MOSA` comment tokens: `severability`, `supplier`, `key`, `standards` (comma
list), `documented`, `cost`, `riskLikelihood`, `riskConsequence`.

## Honest scope

- **Structure** (blocks, block-to-block interfaces) is derived from the real XMI
  encoding. The key gotcha — `xmi:type` is namespaced but a UML `type` reference
  is a plain unqualified attribute — is handled correctly.
- **MOSA attributes** are not native to UML/SysML. A real program would apply a
  MOSA profile; here they come from `@MOSA` **comments** (tool-agnostic). With no
  annotations, modules have no severability and the gate flags
  `MODULE_NO_SEVERABILITY` — it does **not** invent values.
- Ports/connectors (internal block diagrams) and profile-based stereotypes beyond
  Block are not yet mapped; objectives/requirements/Capella `.aird` are future work.

stdlib only (`xml.etree`), so it runs air-gapped.

## Tests

```bash
python test_uml2bom.py   # stdlib; runs against the real excavator + the annotated model
```

`examples/excavator.uml` is vendored from
[github.com/webgme/sysml](https://github.com/webgme/sysml) (MIT) — see the
repository [`NOTICE`](../../NOTICE).
