package mosa

import rego.v1

# Minimal library stub so tests are self-contained (the CLI injects the real
# library/*.yaml at runtime via data.library).
stub_library := {
	"standards": [
		{"id": "FACE-3.1", "open": true},
		{"id": "VENDOR-PROPRIETARY-BUS", "open": false},
	],
	"severability_classes": [
		{"id": "severable"},
		{"id": "non-severable"},
	],
}

# A key interface with an open standard -> no KEY_IFACE_NO_OPEN_STD deny.
test_key_iface_open_std_passes if {
	bom := {
		"modules": [{"id": "M1", "severability": "severable"}, {"id": "M2", "severability": "severable"}],
		"interfaces": [{"id": "IF1", "key": true, "between": ["M1", "M2"], "standards": ["FACE-3.1"]}],
		"objectives": [],
		"requirements": [],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "KEY_IFACE_NO_OPEN_STD"}) == 0
	res.pass == true
}

# A key interface with only a proprietary "standard" -> deny + gate fails.
test_key_iface_proprietary_fails if {
	bom := {
		"modules": [{"id": "M1", "severability": "severable"}, {"id": "M2", "severability": "severable"}],
		"interfaces": [{"id": "IF1", "key": true, "between": ["M1", "M2"], "standards": ["VENDOR-PROPRIETARY-BUS"]}],
		"objectives": [],
		"requirements": [],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "KEY_IFACE_NO_OPEN_STD"}) == 1
	res.pass == false
}

# Unknown standard id is flagged.
test_unknown_standard_flagged if {
	bom := {
		"modules": [{"id": "M1", "severability": "severable"}, {"id": "M2", "severability": "severable"}],
		"interfaces": [{"id": "IF1", "key": true, "between": ["M1", "M2"], "standards": ["FACE-9.9"]}],
		"objectives": [],
		"requirements": [],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "STD_NOT_IN_LIBRARY"}) == 1
}

# Bad severability class is flagged.
test_bad_severability_flagged if {
	bom := {
		"modules": [{"id": "M1", "severability": "made-up"}],
		"interfaces": [],
		"objectives": [],
		"requirements": [],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "MODULE_BAD_SEVERABILITY"}) == 1
}

# A module with NO severability key is flagged (regression: the message must not
# reference the missing value, or the finding would silently vanish).
test_missing_severability_flagged if {
	bom := {
		"modules": [{"id": "M1", "name": "M1"}],
		"interfaces": [],
		"objectives": [],
		"requirements": [],
	}
	res := result with input as bom with data.library as stub_library
	count({f | some f in res.deny; f.code == "MODULE_NO_SEVERABILITY"}) == 1
	res.pass == false
}

# Metrics compute as expected for a clean 1-key-interface manifest.
test_metrics_full_marks if {
	bom := {
		"modules": [{"id": "M1", "severability": "severable"}, {"id": "M2", "severability": "severable"}],
		"interfaces": [{"id": "IF1", "key": true, "between": ["M1", "M2"], "standards": ["FACE-3.1"]}],
		"objectives": [],
		"requirements": [{"id": "R1", "conformance": "verified"}],
	}
	res := result with input as bom with data.library as stub_library
	res.metrics.open_std_coverage_pct == 100
	res.metrics.modularity_score_pct == 100
	res.metrics.conformance_verified_pct == 100
	res.metrics.mosa_index == 100
}

_proprietary_bom := {
	"modules": [{"id": "M1", "severability": "severable"}, {"id": "M2", "severability": "severable"}],
	"interfaces": [{"id": "IF1", "key": true, "between": ["M1", "M2"], "standards": ["VENDOR-PROPRIETARY-BUS"]}],
	"objectives": [],
	"requirements": [],
}

# An active, matching waiver moves the violation to `waived` and the gate PASSES.
test_active_waiver_moves_deny_to_waived if {
	waivers := [{
		"code": "KEY_IFACE_NO_OPEN_STD",
		"subject": "IF1",
		"approver": "PEO Radios",
		"justification": "GFE crypto bus; open standard not available this increment",
		"expires": "2099-12-31",
	}]
	res := result with input as _proprietary_bom with data.library as stub_library with data.waivers as waivers
	res.pass == true
	count(res.deny) == 0
	count({f | some f in res.waived; f.code == "KEY_IFACE_NO_OPEN_STD"}) == 1
	some w in res.waived
	w.approver == "PEO Radios"
}

# A waiver for a different subject does NOT apply; the gate still fails.
test_waiver_wrong_subject_does_not_apply if {
	waivers := [{"code": "KEY_IFACE_NO_OPEN_STD", "subject": "SOMETHING_ELSE", "approver": "x", "expires": "2099-12-31"}]
	res := result with input as _proprietary_bom with data.library as stub_library with data.waivers as waivers
	res.pass == false
	count(res.deny) == 1
	count(res.waived) == 0
}

# A wildcard subject ("*") waiver applies to the matching code.
test_wildcard_waiver_applies if {
	waivers := [{"code": "KEY_IFACE_NO_OPEN_STD", "subject": "*", "approver": "AO", "expires": "2099-12-31"}]
	res := result with input as _proprietary_bom with data.library as stub_library with data.waivers as waivers
	res.pass == true
	count(res.waived) == 1
}

# Extended tier: cost rolls up, cost behind non-severable modules is isolated, and
# a high-risk non-severable module raises an advisory.
test_value_metrics_and_high_risk_warn if {
	bom := {
		"modules": [
			{"id": "M1", "severability": "severable"},
			{"id": "M2", "severability": "non-severable"},
		],
		"interfaces": [{"id": "IF1", "key": true, "between": ["M1", "M2"], "standards": ["FACE-3.1"]}],
		"objectives": [],
		"requirements": [],
		"cost": [
			{"ref": "M1", "pointEstimate": 100},
			{"ref": "M2", "pointEstimate": 900},
		],
		"risks": [{"id": "R", "ref": "M2", "likelihood": 4, "consequence": 5}],
	}
	res := result with input as bom with data.library as stub_library
	res.metrics.total_cost == 1000
	res.metrics.cost_locked_in_non_severable == 900
	count({f | some f in res.warn; f.code == "HIGH_RISK_NON_SEVERABLE"}) == 1
	res.pass == true
}
