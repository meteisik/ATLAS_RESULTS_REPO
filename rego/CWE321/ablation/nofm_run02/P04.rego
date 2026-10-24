package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material used in SecretKeySpec construction."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard that ensures origin_kinds consists only of the literal terminal kind
guard_origin_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every kind in kinds { kind == "literal" }
}

# Guard that ensures origin_values is a non‑empty array of non‑empty strings
guard_origin_values(f) if {
  vals := object.get(f, "origin_values", [])
  is_array(vals)
  count(vals) > 0
  every v in vals { is_string(v); v != "" }
}

# Core positive condition for a violation
core_positive_condition(f) if {
  guard_origin_kinds(f)
  guard_origin_values(f)
}

# Safe contexts are not defined for this policy
allowed_context(f) if {
  false
}

# A fact is a violation if it satisfies the core condition and is not in a safe context
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings construction
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink_member", "")

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
    "sink":        sink,
  }
]

# Human‑readable denial messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}