# Cyber / RMF control-coverage rules (DEMONSTRATION).
#
# Same shape as the MOSA pack on purpose: input = manifest, data.library = the
# control catalog, data.waivers = active waivers, output = data.rmf.result
# { pass, deny, waived, warn, metrics }. This is what "domain-agnostic engine"
# means — only the content differs.
#
# NOT a production RMF tool. A real pack would use OSCAL catalogs/profiles and a
# far richer control/assessment model. See ../README.md.

package rmf

import rego.v1

controls_in := object.get(input, "controls", [])

baseline := object.get(object.get(input, "system", {}), "baseline", "")

known_control(id) if {
	some c in data.library.controls
	c.id == id
}

baseline_controls contains c if {
	some c in data.library.controls
	some b in c.baseline
	b == baseline
}

baseline_ids contains id if {
	some c in baseline_controls
	id := c.id
}

addressed(id) if {
	some ctl in controls_in
	ctl.id == id
}

valid_status := {"implemented", "planned", "not-implemented", "inherited", "not-applicable"}

# ---------------------------------------------------------------------------
# RAW violations (before waivers)
# ---------------------------------------------------------------------------

raw_deny contains f if {
	some ctl in controls_in
	not known_control(ctl.id)
	f := {
		"code": "UNKNOWN_CONTROL",
		"severity": "high",
		"subject": ctl.id,
		"msg": sprintf("control %q is not in the catalog", [ctl.id]),
	}
}

raw_deny contains f if {
	some ctl in controls_in
	not valid_status[ctl.status]
	f := {
		"code": "BAD_STATUS",
		"severity": "high",
		"subject": ctl.id,
		"msg": sprintf("control %q has unrecognized status %q", [ctl.id, ctl.status]),
	}
}

raw_deny contains f if {
	some id in baseline_ids
	not addressed(id)
	f := {
		"code": "BASELINE_CONTROL_MISSING",
		"severity": "high",
		"subject": id,
		"msg": sprintf("baseline control %q is not addressed in the manifest", [id]),
	}
}

raw_deny contains f if {
	some ctl in controls_in
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
# Waivers (same pattern as the MOSA pack)
# ---------------------------------------------------------------------------

waiver_matches_subject(w, f) if w.subject == f.subject

waiver_matches_subject(w, f) if w.subject == "*"

is_waived(f) if {
	some w in data.waivers
	w.code == f.code
	waiver_matches_subject(w, f)
}

deny contains f if {
	some f in raw_deny
	not is_waived(f)
}

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
# WARN (advisory)
# ---------------------------------------------------------------------------

warn contains f if {
	some ctl in controls_in
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
	some ctl in controls_in
	baseline_ids[ctl.id]
	ctl.status in {"implemented", "inherited", "not-applicable"}
	id := ctl.id
}

implemented_pct := round((100 * count(satisfied)) / count(baseline_ids)) if {
	count(baseline_ids) > 0
}

implemented_pct := 0 if count(baseline_ids) == 0

metrics := {
	"baseline": baseline,
	"baseline_controls": count(baseline_ids),
	"implemented_pct": implemented_pct,
	"deny_count": count(deny),
	"waived_count": count(waived),
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
	"waived": waived,
	"warn": warn,
	"metrics": metrics,
}
