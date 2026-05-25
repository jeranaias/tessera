package rmf

import rego.v1

stub_library := {"controls": [
	{"id": "AC-2", "baseline": ["low", "moderate", "high"]},
	{"id": "SC-7", "baseline": ["moderate", "high"]},
]}

# A moderate system that addresses both baseline controls (one implemented, one
# inherited) passes.
test_clean_moderate_passes if {
	bom := {
		"system": {"id": "S1", "name": "Sys", "baseline": "moderate"},
		"controls": [
			{"id": "AC-2", "status": "implemented"},
			{"id": "SC-7", "status": "inherited"},
		],
	}
	res := result with input as bom with data.library as stub_library
	res.pass == true
	res.metrics.implemented_pct == 100
}

# not-implemented baseline control without a POA&M fails the gate.
test_not_implemented_without_poam_fails if {
	bom := {
		"system": {"id": "S1", "name": "Sys", "baseline": "moderate"},
		"controls": [
			{"id": "AC-2", "status": "implemented"},
			{"id": "SC-7", "status": "not-implemented"},
		],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "NOT_IMPLEMENTED_NO_POAM"}) == 1
	res.pass == false
}

# Same, but with a POA&M -> no NOT_IMPLEMENTED_NO_POAM deny.
test_not_implemented_with_poam_ok if {
	bom := {
		"system": {"id": "S1", "name": "Sys", "baseline": "moderate"},
		"controls": [
			{"id": "AC-2", "status": "implemented"},
			{"id": "SC-7", "status": "not-implemented", "poam": "POAM-17"},
		],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "NOT_IMPLEMENTED_NO_POAM"}) == 0
}

# A baseline control omitted from the manifest is flagged.
test_missing_baseline_control_flagged if {
	bom := {
		"system": {"id": "S1", "name": "Sys", "baseline": "moderate"},
		"controls": [{"id": "AC-2", "status": "implemented"}],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "BASELINE_CONTROL_MISSING"; f.subject == "SC-7"}) == 1
}

# Unknown control id is flagged.
test_unknown_control_flagged if {
	bom := {
		"system": {"id": "S1", "name": "Sys", "baseline": "moderate"},
		"controls": [
			{"id": "AC-2", "status": "implemented"},
			{"id": "SC-7", "status": "inherited"},
			{"id": "ZZ-9", "status": "implemented"},
		],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "UNKNOWN_CONTROL"}) == 1
}

# planned control with no target date raises a warning (not a deny).
test_planned_without_date_warns if {
	bom := {
		"system": {"id": "S1", "name": "Sys", "baseline": "moderate"},
		"controls": [
			{"id": "AC-2", "status": "implemented"},
			{"id": "SC-7", "status": "planned"},
		],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.warn; f.code == "PLANNED_NO_DATE"}) == 1
}
