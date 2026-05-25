# MOSA conformance rules pack.
#
# Input  (`input`)        : a MOSA-BOM manifest (see schema/mosa-manifest.schema.json)
# Data   (`data.library`) : merged content of library/*.yaml (standards, objectives,
#                           severability_classes)
#
# Output (`data.mosa.result`): { pass, deny[], warn[], metrics{} }
#   deny  -> gate-failing violations (CI exit 2)
#   warn  -> advisory findings (do not fail the gate)
#
# Philosophy: this file IS the product. New policy = new rule here. New open
# standard = new entry in library/standards.yaml. No platform required.

package mosa

import rego.v1

# ---------------------------------------------------------------------------
# Library helpers
# ---------------------------------------------------------------------------

# Set of standard ids that are open per the library.
open_standard_ids contains id if {
	some s in data.library.standards
	s.open == true
	id := s.id
}

# Is a referenced standard id known to the library at all?
standard_known(id) if {
	some s in data.library.standards
	s.id == id
}

# Valid severability class ids from the taxonomy.
severability_ids contains id if {
	some c in data.library.severability_classes
	id := c.id
}

# ---------------------------------------------------------------------------
# Derived collections
# ---------------------------------------------------------------------------

key_interfaces contains iface if {
	some iface in input.interfaces
	iface.key == true
}

key_interfaces_with_open_std contains iface if {
	some iface in key_interfaces
	some s in iface.standards
	open_standard_ids[s]
}

# ---------------------------------------------------------------------------
# DENY rules (gate-failing)
# ---------------------------------------------------------------------------

# Pillar 4: every designated key interface must reference >=1 open standard.
deny contains f if {
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
deny contains f if {
	some iface in input.interfaces
	some s in iface.standards
	not standard_known(s)
	f := {
		"code": "STD_NOT_IN_LIBRARY",
		"severity": "high",
		"subject": iface.id,
		"msg": sprintf("interface %q claims standard %q which is not in the library", [iface.id, s]),
	}
}

# Pillar 2: every module must carry a valid severability classification.
deny contains f if {
	some m in input.modules
	not severability_ids[m.severability]
	f := {
		"code": "MODULE_BAD_SEVERABILITY",
		"severity": "high",
		"subject": m.id,
		"msg": sprintf("module %q has severability %q which is not a known class", [m.id, m.severability]),
	}
}

# Every asserted MOSA objective must trace to at least one element.
deny contains f if {
	some o in input.objectives
	count(o.tracesTo) == 0
	f := {
		"code": "OBJECTIVE_NO_TRACE",
		"severity": "medium",
		"subject": o.id,
		"msg": sprintf("objective %q traces to nothing", [o.id]),
	}
}

# An interface must connect modules that actually exist in the manifest.
deny contains f if {
	some iface in input.interfaces
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
	some m in input.modules
	m.id == id
}

# ---------------------------------------------------------------------------
# WARN rules (advisory)
# ---------------------------------------------------------------------------

# Key interfaces should be documented (publicly/contractually available spec).
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

# Non-severable modules are a modularity risk worth surfacing.
warn contains f if {
	some m in input.modules
	m.severability == "non-severable"
	f := {
		"code": "MODULE_NON_SEVERABLE",
		"severity": "low",
		"subject": m.id,
		"msg": sprintf("module %q is non-severable (vendor-lock / tech-refresh risk)", [m.id]),
	}
}

# ---------------------------------------------------------------------------
# Metrics & composite MOSA index
# ---------------------------------------------------------------------------

n_key := count(key_interfaces)

open_std_coverage := pct if {
	n_key > 0
	pct := round((100 * count(key_interfaces_with_open_std)) / n_key)
}

open_std_coverage := 0 if n_key == 0

modules_severable := count({m | some m in input.modules; m.severability == "severable"})

modularity_score := round((100 * modules_severable) / count(input.modules)) if {
	count(input.modules) > 0
}

modularity_score := 0 if count(input.modules) == 0

conformance_verified := round((100 * count({r | some r in input.requirements; r.conformance == "verified"})) / count(input.requirements)) if {
	count(input.requirements) > 0
}

conformance_verified := 0 if count(input.requirements) == 0

# Composite index: equal-weighted mean of the three component percentages.
mosa_index := round((open_std_coverage + modularity_score + conformance_verified) / 3)

metrics := {
	"key_interfaces": n_key,
	"open_std_coverage_pct": open_std_coverage,
	"modularity_score_pct": modularity_score,
	"conformance_verified_pct": conformance_verified,
	"mosa_index": mosa_index,
	"deny_count": count(deny),
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
	"warn": warn,
	"metrics": metrics,
}
