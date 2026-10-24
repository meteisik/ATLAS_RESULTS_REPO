package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key‑material provenance so the policy layer can detect hard‑coded effective keys."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f | f := data.drivers.cwe321_facts.facts[_]]

# Guard rules: safe facts where origins are empty
guard_origin_kinds_empty(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) == 0
}

guard_origin_values_empty(f) if {
  values := object.get(f, "origin_values", [])
  count(values) == 0
}

# Core positive condition: sink must be a SecretKeySpec constructor with compile‑time literal origins
core_positive_condition(f) if {
  m := object.get(f, "sink_member", "")
  m == "SecretKeySpec"
  t := object.get(f, "sink_node_type", "")
  t == "class_creator"
  r := object.get(f, "sink_resolved_type", "")
  r == "javax.crypto.spec.SecretKeySpec"
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  values := object.get(f, "origin_values", [])
  count(values) > 0
}

# A fact is a violation if it satisfies the core condition and is not a safe fact
is_violation(f) if {
  core_positive_condition(f)
  not guard_origin_kinds_empty(f)
  not guard_origin_values_empty(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := severity
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

  desc   := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": desc,
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
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}