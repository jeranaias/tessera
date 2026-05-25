#!/usr/bin/env python3
"""uml2bom — derive a MOSA-BOM (Tessera manifest) from a UML/SysML XMI model.

Targets the REAL Papyrus/EMF XMI encoding (validated against the SimpleExcavator
and Airbag Papyrus SysML models), not a guess:

  * Root is <xmi:XMI> with a <uml:Model name="..."> inside.
  * Blocks are <packagedElement xmi:type="uml:Class"> that carry a SysML
    <...:Block base_Class="<class-id>"/> stereotype application.
  * Interfaces are <packagedElement xmi:type="uml:Association"> whose two member
    ends resolve (Property -> `type`) to two distinct blocks.
  * MOSA attributes (which UML/SysML don't natively carry) come from UML comments:
    an <ownedComment annotatedElement="<id> ..."> whose body holds
    `@MOSA severability=...; key=true; standards=A,B; documented=true;
            supplier=...; cost=...; riskLikelihood=...; riskConsequence=...;`
    Absent a comment, a module simply has no severability — and Tessera will
    correctly flag that (the model didn't declare it). A real program would apply
    a MOSA profile; comments are the tool-agnostic stand-in.

Key encoding gotcha handled: `xmi:type` is namespaced, but a UML `type` reference
(e.g. a Property's block) is a PLAIN unqualified attribute. They must not be
conflated.

stdlib only (xml.etree). Usage:
    python uml2bom.py model.uml [-o bom.json]
    python uml2bom.py - < model.uml
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET

_KV_RE = re.compile(r"(\w+)\s*=\s*([^;]+);")


def _ln(tag: str) -> str:
    return tag.split("}")[-1]


def _xmi(e, suffix: str):
    """Namespaced XMI attribute (e.g. xmi:type, xmi:id) by suffix."""
    for k, v in e.attrib.items():
        if k.endswith("}" + suffix):
            return v
    return None


def _num(s):
    s = str(s).strip()
    try:
        return int(s)
    except ValueError:
        try:
            return float(s)
        except ValueError:
            return None


def _parse_mosa(body: str) -> dict:
    """Parse `@MOSA k=v; ...` tokens from a comment body."""
    m = re.search(r"@MOSA\b(.*)", body, re.S)
    if not m:
        return {}
    out = {}
    for km in _KV_RE.finditer(m.group(1)):
        key, raw = km.group(1), km.group(2).strip()
        low = raw.lower()
        if low in ("true", "false"):
            out[key] = low == "true"
        elif len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
            out[key] = raw[1:-1]
        else:
            out[key] = raw
    return out


def _comment_body(e) -> str:
    if e.attrib.get("body"):
        return e.attrib["body"]
    for c in e:
        if _ln(c.tag) == "body":
            return (c.text or "")
    return ""


def parse(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)

    classes: dict[str, str] = {}  # id -> name
    block_ids: set[str] = set()
    prop_type: dict[str, str] = {}  # property id -> block id it is typed by
    model_name = None
    # comments: list of (set(annotated_ids), mosa_dict)
    comments: list[tuple[set, dict]] = []

    for e in root.iter():
        l = _ln(e.tag)
        xt = _xmi(e, "type") or ""
        xid = _xmi(e, "id")
        if l == "Model" and e.attrib.get("name"):
            model_name = model_name or e.attrib.get("name")
        if xt.endswith("Class") and xid:
            classes[xid] = e.attrib.get("name")
        if xt.endswith("Property") and xid:
            prop_type[xid] = e.attrib.get("type")  # PLAIN unqualified UML type ref
        if l == "Block" and e.attrib.get("base_Class"):
            block_ids.add(e.attrib["base_Class"])
        if l == "ownedComment" or xt.endswith("Comment"):
            mosa = _parse_mosa(_comment_body(e))
            if mosa:
                annotated = set((e.attrib.get("annotatedElement") or "").split())
                comments.append((annotated, mosa))

    # Modules: SysML blocks; fall back to all classes if no stereotypes present.
    module_ids = block_ids if block_ids else set(classes)

    def mosa_for(elem_id):
        merged = {}
        for ids, mosa in comments:
            if elem_id in ids:
                merged.update(mosa)
        return merged

    program = {"id": model_name or "UNKNOWN", "name": model_name or "Unknown Program"}

    modules, cost_entries, risk_entries = [], [], []
    for cid in sorted(module_ids, key=lambda i: classes.get(i) or i):
        name = classes.get(cid) or cid
        meta = mosa_for(cid)
        mod = {"id": name, "name": name, "sourceRef": f"xmi://{cid}"}
        if "severability" in meta:
            mod["severability"] = meta["severability"]
        if "supplier" in meta:
            mod["supplier"] = meta["supplier"]
        modules.append(mod)
        if "cost" in meta and _num(meta["cost"]) is not None:
            cost_entries.append({"ref": name, "pointEstimate": _num(meta["cost"])})
        rl, rc = _num(meta.get("riskLikelihood")), _num(meta.get("riskConsequence"))
        if rl is not None and rc is not None:
            risk_entries.append({"id": "RISK-" + name, "ref": name, "likelihood": rl, "consequence": rc})

    def block_of(prop_id):
        return classes.get(prop_type.get(prop_id))

    interfaces = []
    for e in root.iter():
        if _ln(e.tag) != "packagedElement" or not (_xmi(e, "type") or "").endswith("Association"):
            continue
        ends = (e.attrib.get("memberEnd") or "").split()
        blocks = []
        for pid in ends:
            b = block_of(pid)
            if b and b not in blocks:
                blocks.append(b)
        if len(blocks) < 2:
            continue  # not a module-to-module interface
        name = e.attrib.get("name") or ("IF-" + (_xmi(e, "id") or ""))
        meta = mosa_for(_xmi(e, "id"))
        standards = []
        if meta.get("standards"):
            standards = [s.strip() for s in str(meta["standards"]).split(",") if s.strip()]
        interfaces.append({
            "id": name,
            "name": name,
            "key": bool(meta.get("key", False)),
            "between": blocks[:2],
            "standards": standards,
            "documented": bool(meta.get("documented", False)),
            "sourceRef": f"xmi://{_xmi(e, 'id')}",
        })

    bom = {"mosaManifestVersion": "0.1", "program": program, "modules": modules, "interfaces": interfaces}
    if cost_entries:
        bom["cost"] = cost_entries
    if risk_entries:
        bom["risks"] = risk_entries
    return bom


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Derive a MOSA-BOM from a UML/SysML XMI model.")
    ap.add_argument("model", help="path to a .uml/.xmi model, or - for stdin")
    ap.add_argument("-o", "--out", help="write manifest here (default: stdout)")
    args = ap.parse_args(argv)
    text = sys.stdin.read() if args.model == "-" else open(args.model, encoding="utf-8").read()
    out = json.dumps(parse(text), indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
