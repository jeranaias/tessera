# Cyber / RMF control-coverage rules (DEMONSTRATION).
#
# Same shape as the MOSA pack on purpose: input = manifest, data.library = the
# control catalog, output = data.rmf.result {pass, deny, warn, metrics}. This is
# what "domain-agnostic engine" means — only the content differs.
#
# NOT a production RMF tool. A real pack would use OSCAL catalogs/profiles and a
# far richer control/assessment model. See ../README.md.

package rmf

import rego.v1

known_control(id) if {
	some c in data.library.controls
	c.id == id
}

# Controls that apply to this system's baseline.
baseline_controls contains c if {
	some c in data.library.controls
	some b in c.baseline
	b == input.system.baseline
}

baseline_ids contains id if {
	some c in baseline_controls
	id := c.id
}

addressed(id) if {
	some ctl in input.controls
	ctl.id == id
}

valid_status := {"implemented", "planned", "not-implemented", "inherited", "not-applicable"}

# ---------------------------------------------------------------------------
# DENY (gate-failing)
# ---------------------------------------------------------------------------

# A claimed control must exist in the catalog.
deny contains f if {
	some ctl in input.controls
	not known_control(ctl.id)
	f := {
		"code": "UNKNOWN_CONTROL",
		"severity": "high",
		"subject": ctl.id,
		"msg": sprintf("control %q is not in the catalog", [ctl.id]),
	}
}

# Status must be a recognized value.
deny contains f if {
	some ctl in input.controls
	not valid_status[ctl.status]
	f := {
		"code": "BAD_STATUS",
		"severity": "high",
		"subject": ctl.id,
		"msg": sprintf("control %q has unrecognized status %q", [ctl.id, ctl.status]),
	}
}

# Every control in the system's baseline must be addressed in the manifest.
deny contains f if {
	some id in baseline_ids
	not addressed(id)
	f := {
		"code": "BASELINE_CONTROL_MISSING",
		"severity": "high",
		"subject": id,
		"msg": sprintf("baseline control %q is not addressed in the manifest", [id]),
	}
}

# A baseline control that is not-implemented must carry a POA&M.
deny contains f if {
	some ctl in input.controls
	baseline_ids[ctl.id]
	ctl.status == "not-implemented"
	not ctl.poam
	f := {
		"code": "NOT_IMPLEMENTED_NO_POAM",
		"severity": "high",
		"subject": ctl.id,
		"msg": sprintf("baseline control %q is not-implemented with no POA&M", [ctl.id]),
	}
}

# ---------------------------------------------------------------------------
# WARN (advisory)
# ---------------------------------------------------------------------------

warn contains f if {
	some ctl in input.controls
	ctl.status == "planned"
	not ctl.targetDate
	f := {
		"code": "PLANNED_NO_DATE",
		"severity": "low",
		"subject": ctl.id,
		"msg": sprintf("planned control %q has no target date", [ctl.id]),
	}
}

# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

satisfied contains id if {
	some ctl in input.controls
	baseline_ids[ctl.id]
	ctl.status in {"implemented", "inherited", "not-applicable"}
	id := ctl.id
}

implemented_pct := round((100 * count(satisfied)) / count(baseline_ids)) if {
	count(baseline_ids) > 0
}

implemented_pct := 0 if count(baseline_ids) == 0

metrics := {
	"baseline": input.system.baseline,
	"baseline_controls": count(baseline_ids),
	"implemented_pct": implemented_pct,
	"deny_count": count(deny),
	"warn_count": count(warn),
}

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

default pass := false

pass if count(deny) == 0

result := {
	"pass": pass,
	"deny": deny,
	"warn": warn,
	"metrics": metrics,
}
