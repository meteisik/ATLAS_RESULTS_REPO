package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material."

primary_fact_type := "crypto_key_material_fact"

driver_facts := [f | f := data.drivers.cwe321_facts.facts[_]]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds { kind == "literal" }

  vals := object.get(f, "origin_values", [])
  count(vals) > 0
  every val in vals { val != "" }

  sm := object.get(f, "sink_member", "")
  sm == "newInstance"

  sn := object.get(f, "sink_node_type", "")
  sn == "method_invocation"

  sr := object.get(f, "sink_resolved_type", "")
  sr == "javax.crypto.spec.SecretKeySpec"

  kca := object.get(f, "key_consumer_ast_id", 0)
  kca == 0
}

exclude_consumed_keys(f) if {
  kca := object.get(f, "key_consumer_ast_id", 0)
  kca != 0
}

exclude_runtime_origin_keys(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

is_violation(f) if {
  core_positive_condition(f)
  not exclude_consumed_keys(f)
  not exclude_runtime_origin_keys(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

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