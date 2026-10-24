package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material that is compile‑time constant."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

# Canonical list of driver facts
driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# -------------------------------------------------------------------
# Guard rules – exclude facts that are safe.
# -------------------------------------------------------------------
guard_origin_contains_non_literal(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}

guard_origin_mixed_literal_and_non_literal(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some lit in kinds
  lit == "literal"
  some other in kinds
  other != "literal"
}

# Prevent the algorithm field from being used as a violation trigger.
guard_algorithm_not_violation_trigger(f) if {
  false
}

# -------------------------------------------------------------------
# Core positive condition – signals a violating fact.
# -------------------------------------------------------------------
core_positive_condition(f) if {
  # origin_kinds must be exactly ["literal"]
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) == 1
  kinds[0] == "literal"

  # origin_values must be a non‑empty list
  vals := object.get(f, "origin_values", [])
  is_array(vals)
  count(vals) > 0

  # sink must be a SecretKeySpec constructor
  object.get(f, "sink_member", "") == "SecretKeySpec"
  object.get(f, "sink_node_type", "") == "class_creator"
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.SecretKeySpec"
}

# -------------------------------------------------------------------
# Violation predicate – core condition minus any guard exclusions.
# -------------------------------------------------------------------
is_violation(f) if {
  core_positive_condition(f)
  not guard_origin_contains_non_literal(f)
  not guard_origin_mixed_literal_and_non_literal(f)
  not guard_algorithm_not_violation_trigger(f)
}

# -------------------------------------------------------------------
# Findings – normalized representation of each violation.
# -------------------------------------------------------------------
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": desc,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        object.get(f, "sink", ""),
  }
]

# -------------------------------------------------------------------
# Deny – human‑readable messages for each finding.
# -------------------------------------------------------------------
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}