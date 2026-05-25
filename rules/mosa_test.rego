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
