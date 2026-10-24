package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard rules – safe contexts
guard_runtime_origin_kind(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}

guard_missing_origin_value(f) if {
  vals := object.get(f, "origin_values", [])
  count(vals) == 0
}

guard_mixed_origin_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  some k in kinds
  k != "literal"
}

# Any guard true means the fact is allowed (safe)
allowed_context(f) if { guard_runtime_origin_kind(f) }
allowed_context(f) if { guard_missing_origin_value(f) }
allowed_context(f) if { guard_mixed_origin_kinds(f) }

# Core positive condition – the exact signature of a violating fact
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "crypto_key_material_fact"

  kinds := object.get(f, "origin_kinds", [])
  count(kinds) == 1
  every k in kinds { k == "literal" }

  vals := object.get(f, "origin_values", [])
  count(vals) > 0
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", "")

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