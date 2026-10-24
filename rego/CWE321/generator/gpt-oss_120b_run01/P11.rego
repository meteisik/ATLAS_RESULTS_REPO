package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material that is compile‑time constant."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard: exclude any fact where an origin kind is not "literal"
guard_non_literal_origin_kind(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}

# Guard: exclude facts where origin_values list is empty or missing
guard_runtime_origin_value(f) if {
  vals := object.get(f, "origin_values", [])
  count(vals) == 0
}

# Core positive condition: fact is of correct type, all origins are literals, and there is at least one origin value
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "crypto_key_material_fact"

  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every k in kinds { k == "literal" }

  vals := object.get(f, "origin_values", [])
  is_array(vals)
  count(vals) > 0
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not guard_non_literal_origin_kind(f)
  not guard_runtime_origin_value(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink  := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
  }
]

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id,
    v.title,
    file,
    line,
  ])
}