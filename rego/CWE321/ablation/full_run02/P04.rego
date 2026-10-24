package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material."

primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard rule: true when key material is not compile‑time fixed.
safe_key_guard(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}
safe_key_guard(f) if {
  values := object.get(f, "origin_values", [])
  count(values) == 0
}

# Core positive condition: all origins are literal and have non‑empty values.
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds { kind == "literal" }

  values := object.get(f, "origin_values", [])
  count(values) > 0
  every val in values { val != "" }
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_key_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink_member", "")

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink
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