package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can detect hard‑coded effective keys."

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

runtime_key_guard(f) if {
  key_consumer := object.get(f, "key_consumer_ast_id", 0)
  key_consumer != 0
}

non_literal_origin_guard(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  some k in kinds
  k != "literal"
}

core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "crypto_key_material_fact"

  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every k in kinds { k == "literal" }

  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
  every v in values { v != "" }
}

is_violation(f) if {
  core_positive_condition(f)
  not runtime_key_guard(f)
  not non_literal_origin_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls  := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

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