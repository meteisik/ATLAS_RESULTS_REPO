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

skip_runtime_provided_keys(f) if {
  key_consumer := object.get(f, "key_consumer_ast_id", 0)
  key_consumer != 0
}

core_positive_condition(f) if {
  kind_list := object.get(f, "origin_kinds", [])
  is_array(kind_list)
  count(kind_list) > 0

  val_list := object.get(f, "origin_values", [])
  is_array(val_list)
  count(val_list) > 0

  t := object.get(f, "fact_type", "")
  t == "crypto_key_material_fact"
}

allowed_context(f) if {
  false
}

is_violation(f) if {
  core_positive_condition(f)
  not skip_runtime_provided_keys(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := severity
  ftype := object.get(f, "fact_type", "")
  sink := object.get(f, "sink_member", "")

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
    v.policy_id, v.title, file, line,
  ])
}