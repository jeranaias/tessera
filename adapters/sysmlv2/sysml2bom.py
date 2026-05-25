#!/usr/bin/env python3
"""sysml2bom — derive a MOSA-BOM (Tessera manifest) from a SysML v2 textual model.

This is the gap-closer described in ../../docs/VIABILITY.md. It moves Tessera's
output from ATTESTATION (signing a hand-written claim) toward VERIFICATION
(signing facts DERIVED from the model). A program that hand-edits its manifest to
claim, say, FACE conformance it doesn't have cannot fool a manifest derived from
the model itself.

SUPPORTED SUBSET — documented honestly; this is NOT a full SysML v2 parser:

    package <Name> { ... }
    @Program { id="..."; name="..."; milestone="..."; }        // optional, top-level
    part <usage> [: <Def>] {
        @MOSA { severability="..."; supplier="..."; }           // makes it a module
    }
    connection <name> [: <Def>] connect <a> to <b> {
        @MOSA { key=true; standards="A,B"; documented=true; }
    }
    @MOSAObjective { id="OBJ-..."; tracesTo="a,b"; }            (anywhere)
    requirement <name> { @MOSA { conformance="verified"; tracesTo="x"; } }

Conventions:
  * A `part` becomes a MOSA module iff its body carries an `@MOSA` block with
    `severability`, appearing BEFORE any nested part/connection (so container
    parts are not mistaken for modules).
  * `standards` is a comma-separated string; it is split into a list.
  * Line (//) and block (/* */) comments are ignored.

NOT YET DERIVED (still self-declared if needed): cost, risk. See
../../docs/VIABILITY.md.

Usage:
    python sysml2bom.py model.sysml            # JSON manifest to stdout
    python sysml2bom.py model.sysml -o bom.json
    python sysml2bom.py - < model.sysml        # read from stdin
"""
from __future__ import annotations

import argparse
import json
import re
import sys

_KEYWORD_RE = re.compile(r"\b(?:part|connection)\b")
_PART_RE = re.compile(r"\bpart\s+(?!def\b)(\w+)\s*(?::\s*[\w.]+)?\s*\{")
_CONN_RE = re.compile(
    r"\bconnection\s+(\w+)\s*(?::\s*[\w.]+)?\s*connect\s+(\w+)\s+to\s+(\w+)\s*([{;])"
)
_KV_RE = re.compile(r"(\w+)\s*=\s*([^;]+);")


def strip_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r"//[^\n]*", "", s)
    return s


def matching_brace(s: str, i: int) -> int:
    """Index of the '}' that matches the '{' at s[i]."""
    depth = 0
    for j in range(i, len(s)):
        if s[j] == "{":
            depth += 1
        elif s[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    raise ValueError("unbalanced braces in model")


def parse_kv(block: str) -> dict:
    out: dict = {}
    for m in _KV_RE.finditer(block):
        key, raw = m.group(1), m.group(2).strip()
        low = raw.lower()
        if low in ("true", "false"):
            out[key] = low == "true"
        elif len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
            out[key] = raw[1:-1]
        else:
            out[key] = raw
    return out


def find_mosa(block: str) -> dict | None:
    m = re.search(r"@MOSA\s*\{", block)
    if not m:
        return None
    open_i = block.index("{", m.start())
    close_i = matching_brace(block, open_i)
    return parse_kv(block[open_i + 1 : close_i])


def _direct_prefix(block: str) -> str:
    """Block content up to the first nested part/connection (so nested @MOSA
    blocks are not attributed to a container part)."""
    m = _KEYWORD_RE.search(block)
    return block[: m.start()] if m else block


def parse(text: str) -> dict:
    text = strip_comments(text)

    program = {"id": "UNKNOWN", "name": "Unknown Program"}
    pm = re.search(r"@Program\s*\{", text)
    if pm:
        oi = text.index("{", pm.start())
        kv = parse_kv(text[oi + 1 : matching_brace(text, oi)])
        for k in ("id", "name", "milestone"):
            if k in kv:
                program[k] = kv[k]
    else:
        pkg = re.search(r"\bpackage\s+([\w.]+)", text)
        if pkg:
            program["id"] = program["name"] = pkg.group(1)

    modules = []
    for m in _PART_RE.finditer(text):
        name = m.group(1)
        oi = m.end() - 1  # the '{'
        body = text[oi + 1 : matching_brace(text, oi)]
        meta = find_mosa(_direct_prefix(body))
        if not meta or "severability" not in meta:
            continue
        mod = {
            "id": name,
            "name": name,
            "severability": meta["severability"],
            "sourceRef": f"sysmlv2://{program['id']}.{name}",
        }
        if "supplier" in meta:
            mod["supplier"] = meta["supplier"]
        modules.append(mod)

    interfaces = []
    for m in _CONN_RE.finditer(text):
        name, a, b, brace = m.group(1), m.group(2), m.group(3), m.group(4)
        meta: dict = {}
        if brace == "{":
            oi = m.end() - 1
            meta = find_mosa(text[oi + 1 : matching_brace(text, oi)]) or {}
        standards = []
        if meta.get("standards"):
            standards = [s.strip() for s in str(meta["standards"]).split(",") if s.strip()]
        interfaces.append(
            {
                "id": name,
                "name": name,
                "key": bool(meta.get("key", False)),
                "between": [a, b],
                "standards": standards,
                "documented": bool(meta.get("documented", False)),
                "sourceRef": f"sysmlv2://{program['id']}.{name}",
            }
        )

    objectives = []
    for m in re.finditer(r"@MOSAObjective\s*\{", text):
        oi = text.index("{", m.start())
        kv = parse_kv(text[oi + 1 : matching_brace(text, oi)])
        if "id" in kv:
            traces = [s.strip() for s in str(kv.get("tracesTo", "")).split(",") if s.strip()]
            objectives.append({"id": kv["id"], "tracesTo": traces})

    requirements = []
    for m in re.finditer(r"\brequirement\s+(\w+)\s*\{", text):
        name = m.group(1)
        oi = m.end() - 1
        meta = find_mosa(text[oi + 1 : matching_brace(text, oi)]) or {}
        req = {"id": name, "conformance": meta.get("conformance", "none")}
        traces = [s.strip() for s in str(meta.get("tracesTo", "")).split(",") if s.strip()]
        if traces:
            req["tracesTo"] = traces
        requirements.append(req)

    bom = {
        "mosaManifestVersion": "0.1",
        "program": program,
        "modules": modules,
        "interfaces": interfaces,
    }
    if objectives:
        bom["objectives"] = objectives
    if requirements:
        bom["requirements"] = requirements
    return bom


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Derive a MOSA-BOM from a SysML v2 textual model.")
    ap.add_argument("model", help="path to a .sysml model, or - for stdin")
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
