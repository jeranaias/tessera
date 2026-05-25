#!/usr/bin/env python3
"""Self-contained tests for sysml2bom (stdlib only — no pytest required).

Run directly:   python test_sysml2bom.py
Or via pytest:  pytest adapters/sysmlv2/
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sysml2bom  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
_RADIO = os.path.join(_HERE, "examples", "radio.sysml")


def _radio_bom():
    with open(_RADIO, encoding="utf-8") as f:
        return sysml2bom.parse(f.read())


def test_program_derived_from_model():
    bom = _radio_bom()
    assert bom["program"]["id"] == "PRG-SDR-001"
    assert bom["program"]["milestone"] == "MS-B"


def test_four_modules_derived():
    mods = {m["id"]: m for m in _radio_bom()["modules"]}
    assert set(mods) == {"rf", "waveform", "control", "crypto"}
    assert mods["rf"]["severability"] == "severable"
    assert mods["rf"]["supplier"] == "VendorA"


def test_container_part_is_not_a_module():
    # `radio` is a container part with no direct @MOSA — must not be a module.
    ids = {m["id"] for m in _radio_bom()["modules"]}
    assert "radio" not in ids


def test_crypto_is_non_severable():
    mods = {m["id"]: m for m in _radio_bom()["modules"]}
    assert mods["crypto"]["severability"] == "non-severable"


def test_key_interface_standards_reflect_the_model():
    # The whole point: standards come from the MODEL, not a claim. The crypto link
    # is proprietary in the model, so the derived manifest must say so.
    ifaces = {i["id"]: i for i in _radio_bom()["interfaces"]}
    assert ifaces["ifCtrlCrypto"]["key"] is True
    assert ifaces["ifCtrlCrypto"]["standards"] == ["VENDOR-PROPRIETARY-BUS"]
    assert ifaces["ifCtrlCrypto"]["documented"] is False
    # multi-standard splitting
    assert ifaces["ifRfWf"]["standards"] == ["MORA", "REDHAWK"]


def test_non_key_interface_defaults():
    ifaces = {i["id"]: i for i in _radio_bom()["interfaces"]}
    assert ifaces["ifInternal"]["key"] is False
    assert ifaces["ifInternal"]["standards"] == []
    assert ifaces["ifInternal"]["between"] == ["control", "rf"]


def test_objectives_derived_from_model():
    objs = {o["id"]: o for o in _radio_bom().get("objectives", [])}
    assert "OBJ-OPEN-STANDARDS" in objs
    assert objs["OBJ-MODULAR-DESIGN"]["tracesTo"] == ["rf", "waveform", "control"]


def test_requirements_derived_from_model():
    reqs = {r["id"]: r for r in _radio_bom().get("requirements", [])}
    assert reqs["reqFaceConformance"]["conformance"] == "verified"
    assert reqs["reqFaceConformance"]["tracesTo"] == ["ifRfWf"]
    assert reqs["reqDdsConformance"]["conformance"] == "planned"


def test_cost_and_risk_derived():
    bom = _radio_bom()
    cost = {c["ref"]: c for c in bom.get("cost", [])}
    assert cost["crypto"]["pointEstimate"] == 1200000
    assert cost["rf"]["pointEstimate"] == 300000
    risks = {r["ref"]: r for r in bom.get("risks", [])}
    assert risks["crypto"]["likelihood"] == 4
    assert risks["crypto"]["consequence"] == 5


def test_derivation_defeats_a_false_claim():
    # If a model is edited to use an open standard, the derived manifest changes
    # accordingly — you cannot make the manifest lie about what the model says.
    with open(_RADIO, encoding="utf-8") as f:
        honest = f.read()
    cheated = honest.replace('standards = "VENDOR-PROPRIETARY-BUS"', 'standards = "FACE-3.1"')
    bom = sysml2bom.parse(cheated)
    ifaces = {i["id"]: i for i in bom["interfaces"]}
    assert ifaces["ifCtrlCrypto"]["standards"] == ["FACE-3.1"]


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
