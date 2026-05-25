# MOSA conformance rules pack.
#
# Input  (`input`)        : a MOSA-BOM manifest (see schema/manifest.schema.json)
# Data   (`data.library`) : merged content of library/*.yaml (standards, objectives,
#                           severability_classes)
# Data   (`data.waivers`) : active (non-expired) waivers, injected by the engine
#                           (see --waivers). Each: {code, subject|"*", justification,
#                           approver, expires}.
#
# Output (`data.mosa.result`): { pass, deny[], waived[], warn[], metrics{} }
#   raw violations -> if covered by an active waiver, move to `waived` (recorded
#   with approver/justification, but DO NOT fail the gate); otherwise `deny`.
#   This is how MOSA's "to the maximum extent practicable" is honored: exceptions
#   are allowed, but only when justified, attributed, and time-bounded.
#
# Optional manifest sections (requirements, objectives) are normalized with
# object.get defaults so a DERIVED manifest that omits them still evaluates fully.
#
# Philosophy: this file IS the product. New policy = new rule here. New open
# standard = new entry in library/standards.yaml. No platform required.

package mosa

import rego.v1

# ---------------------------------------------------------------------------
# Normalized inputs (robust to missing optional keys)
# ---------------------------------------------------------------------------

modules_in := object.get(input, "modules", [])

ifaces_in := object.get(input, "interfaces", [])

reqs_in := object.get(input, "requirements", [])

objs_in := object.get(input, "objectives", [])

cost_in := object.get(input, "cost", [])

risks_in := object.get(input, "risks", [])

# Severability of a module by id (undefined if not found).
severability_of(id) := s if {
	some m in modules_in
	m.id == id
	s := m.severability
}

# ---------------------------------------------------------------------------
# Library helpers
# ---------------------------------------------------------------------------

open_standard_ids contains id if {
	some s in data.library.standards
	s.open == true
	id := s.id
}

standard_known(id) if {
	some s in data.library.standards
	s.id == id
}

severability_ids contains id if {
	some c in data.library.severability_classes
	id := c.id
}

# ---------------------------------------------------------------------------
# Derived collections
# ---------------------------------------------------------------------------

key_interfaces contains iface if {
	some iface in ifaces_in
	iface.key == true
}

# ---------------------------------------------------------------------------
# RAW violations (before waivers)
# ---------------------------------------------------------------------------

# Pillar 4: every designated key interface must reference >=1 open standard.
raw_deny contains f if {
	some iface in key_interfaces
	count({s | some s in iface.standards; open_standard_ids[s]}) == 0
	f := {
		"code": "KEY_IFACE_NO_OPEN_STD",
		"severity": "high",
		"subject": iface.id,
		"msg": sprintf("key interface %q references no open standard from the library", [iface.id]),
	}
}

# A claimed standard must exist in the library (catch typos / unvetted standards).
raw_deny contains f if {
	some iface in ifaces_in
	some s in iface.standards
	not standard_known(s)
	f := {
		"code": "STD_NOT_IN_LIBRARY",
		"severity": "high",
		"subject": iface.id,
		"msg": sprintf("interface %q claims standard %q which is not in the library", [iface.id, s]),
	}
}

# Pillar 2: every module must carry a severability classification...
raw_deny contains f if {
	some m in modules_in
	not m.severability
	f := {
		"code": "MODULE_NO_SEVERABILITY",
		"severity": "high",
		"subject": m.id,
		"msg": sprintf("module %q has no severability classification (model did not declare it)", [m.id]),
	}
}

# ...and it must be one of the known classes.
raw_deny contains f if {
	some m in modules_in
	m.severability
	not severability_ids[m.severability]
	f := {
		"code": "MODULE_BAD_SEVERABILITY",
		"severity": "high",
		"subject": m.id,
		"msg": sprintf("module %q has severability %q which is not a known class", [m.id, m.severability]),
	}
}

# Every asserted MOSA objective must trace to at least one element.
raw_deny contains f if {
	some o in objs_in
	count(o.tracesTo) == 0
	f := {
		"code": "OBJECTIVE_NO_TRACE",
		"severity": "medium",
		"subject": o.id,
		"msg": sprintf("objective %q traces to nothing", [o.id]),
	}
}

# An interface must connect modules that actually exist in the manifest.
raw_deny contains f if {
	some iface in ifaces_in
	some endpoint in iface.between
	not module_exists(endpoint)
	f := {
		"code": "IFACE_DANGLING_ENDPOINT",
		"severity": "medium",
		"subject": iface.id,
		"msg": sprintf("interface %q connects unknown module %q", [iface.id, endpoint]),
	}
}

module_exists(id) if {
	some m in modules_in
	m.id == id
}

# ---------------------------------------------------------------------------
# Waivers: split raw violations into deny (still failing) vs waived (accepted)
# ---------------------------------------------------------------------------

waiver_matches_subject(w, f) if w.subject == f.subject

waiver_matches_subject(w, f) if w.subject == "*"

is_waived(f) if {
	some w in data.waivers
	w.code == f.code
	waiver_matches_subject(w, f)
}

# Effective denials = raw violations NOT covered by an active waiver.
deny contains f if {
	some f in raw_deny
	not is_waived(f)
}

# Waived findings are recorded (with attribution) but do not fail the gate.
waived contains wf if {
	some f in raw_deny
	some w in data.waivers
	w.code == f.code
	waiver_matches_subject(w, f)
	wf := {
		"code": f.code,
		"subject": f.subject,
		"severity": f.severity,
		"msg": f.msg,
		"waived": true,
		"approver": object.get(w, "approver", ""),
		"justification": object.get(w, "justification", ""),
		"expires": object.get(w, "expires", ""),
	}
}

# ---------------------------------------------------------------------------
# WARN rules (advisory)
# ---------------------------------------------------------------------------

warn contains f if {
	some iface in key_interfaces
	not iface.documented
	f := {
		"code": "KEY_IFACE_UNDOCUMENTED",
		"severity": "low",
		"subject": iface.id,
		"msg": sprintf("key interface %q is not marked documented", [iface.id]),
	}
}

warn contains f if {
	some m in modules_in
	m.severability == "non-severable"
	f := {
		"code": "MODULE_NON_SEVERABLE",
		"severity": "low",
		"subject": m.id,
		"msg": sprintf("module %q is non-severable (vendor-lock / tech-refresh risk)", [m.id]),
	}
}

# Pillar 3: interfaces exist but none are designated key — likely an incomplete
# "designate key interfaces" step.
warn contains f if {
	count(ifaces_in) > 0
	n_key == 0
	f := {
		"code": "NO_KEY_INTERFACES_DESIGNATED",
		"severity": "low",
		"subject": "(program)",
		"msg": "interfaces exist but none are designated key (MOSA pillar 3)",
	}
}

# Extended tier: a non-severable module carrying high risk (likelihood x
# consequence >= 15 of 25) is where modularity gaps are most expensive to ignore.
warn contains f if {
	some r in risks_in
	severability_of(r.ref) == "non-severable"
	exposure := r.likelihood * r.consequence
	exposure >= 15
	f := {
		"code": "HIGH_RISK_NON_SEVERABLE",
		"severity": "low",
		"subject": r.ref,
		"msg": sprintf("non-severable module %q carries high risk (exposure %v of 25)", [r.ref, exposure]),
	}
}

# ---------------------------------------------------------------------------
# Metrics & composite MOSA index
# ---------------------------------------------------------------------------

n_key := count(key_interfaces)

key_interfaces_with_open_std contains iface if {
	some iface in key_interfaces
	some s in iface.standards
	open_standard_ids[s]
}

open_std_coverage := round((100 * count(key_interfaces_with_open_std)) / n_key) if n_key > 0

open_std_coverage := 0 if n_key == 0

modules_severable := count({m | some m in modules_in; m.severability == "severable"})

modularity_score := round((100 * modules_severable) / count(modules_in)) if count(modules_in) > 0

modularity_score := 0 if count(modules_in) == 0

conformance_verified := round((100 * count({r | some r in reqs_in; r.conformance == "verified"})) / count(reqs_in)) if {
	count(reqs_in) > 0
}

conformance_verified := 0 if count(reqs_in) == 0

mosa_index := round((open_std_coverage + modularity_score + conformance_verified) / 3)

# Value view (extended tier): total cost, and the cost sitting behind modules that
# can't be re-competed/refreshed without redesign — what a PM most wants surfaced.
total_cost := sum([c.pointEstimate | some c in cost_in])

cost_locked_in_non_severable := sum([c.pointEstimate |
	some c in cost_in
	severability_of(c.ref) == "non-severable"
])

metrics := {
	"key_interfaces": n_key,
	"open_std_coverage_pct": open_std_coverage,
	"modularity_score_pct": modularity_score,
	"conformance_verified_pct": conformance_verified,
	"mosa_index": mosa_index,
	"total_cost": total_cost,
	"cost_locked_in_non_severable": cost_locked_in_non_severable,
	"deny_count": count(deny),
	"waived_count": count(waived),
	"warn_count": count(warn),
}

# ---------------------------------------------------------------------------
# Top-level result the CLI evaluates
# ---------------------------------------------------------------------------

default pass := false

pass if count(deny) == 0

result := {
	"pass": pass,
	"deny": deny,
	"waived": waived,
	"warn": warn,
	"metrics": metrics,
}
