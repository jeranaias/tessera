#!/usr/bin/env python3
"""Self-contained tests for uml2bom (stdlib only — no pytest required).

Run:   python test_uml2bom.py
Or:    pytest adapters/xmi/
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uml2bom  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))


def _bom(name):
    with open(os.path.join(_HERE, "examples", name), encoding="utf-8") as f:
        return uml2bom.parse(f.read())


# --- real Papyrus model (SimpleExcavator, MIT) : structure only, no MOSA attrs ---

def test_real_excavator_blocks_and_interfaces():
    bom = _bom("excavator.uml")
    ids = {m["id"] for m in bom["modules"]}
    assert len(bom["modules"]) == 9
    assert {"Excavator", "Boom", "Arm"} <= ids
    # 9 associations between blocks become interfaces
    assert len(bom["interfaces"]) == 9
    for i in bom["interfaces"]:
        assert len(i["between"]) == 2


def test_real_excavator_has_no_mosa_attrs():
    # The real model declares no MOSA metadata, so severability is absent — and
    # Tessera will (correctly) flag that. We must NOT invent it.
    bom = _bom("excavator.uml")
    assert all("severability" not in m for m in bom["modules"])


# --- annotated model (faithful encoding + @MOSA comments) : attribute extraction ---

def test_annotated_module_attrs_from_comments():
    mods = {m["id"]: m for m in _bom("radio-annotated.uml")["modules"]}
    assert mods["RF"]["severability"] == "severable"
    assert mods["RF"]["supplier"] == "VendorA"
    assert mods["Crypto"]["severability"] == "non-severable"


def test_annotated_interface_attrs_from_comments():
    ifaces = {i["id"]: i for i in _bom("radio-annotated.uml")["interfaces"]}
    assert ifaces["ifRfWf"]["key"] is True
    assert ifaces["ifRfWf"]["standards"] == ["MORA", "REDHAWK"]
    assert ifaces["ifWfCrypto"]["standards"] == ["VENDOR-PROPRIETARY-BUS"]
    assert ifaces["ifWfCrypto"]["documented"] is False


def test_annotated_cost_and_risk_derived():
    bom = _bom("radio-annotated.uml")
    cost = {c["ref"]: c for c in bom.get("cost", [])}
    assert cost["Crypto"]["pointEstimate"] == 1200000
    risks = {r["ref"]: r for r in bom.get("risks", [])}
    assert risks["Crypto"]["likelihood"] == 4


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"  ERROR {t.__name__}: {e}")
    print(f"{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run())
