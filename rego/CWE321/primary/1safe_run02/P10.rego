package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can detect hard-coded effective keys."

driver_key := "cwe321_facts"

driver_facts := [f | f := data.drivers.cwe321_facts.facts[_]]

guard_runtime_origin(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

core_positive_condition(f) if {
  fact_type := object.get(f, "fact_type", "")
  fact_type == "crypto_key_material_fact"

  kinds := object.get(f, "origin_kinds", [])
  kinds == ["literal", "literal"]

  values := object.get(f, "origin_values", [])
  count(values) > 0

  sink_type := object.get(f, "sink_resolved_type", "")
  sink_type == "javax.crypto.spec.SecretKeySpec"

  sink_member := object.get(f, "sink_member", "")
  sink_member == "newInstance"

  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_runtime_origin(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", "")

  sink := object.get(f, "sink_member", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "call_ast_id", 0)

  v := {
    "policy_id": policy_id,
    "title": title,
    "severity": sev,
    "description": description,
    "file": file,
    "class": cls,
    "method": method,
    "line": line,
    "fact_type": ftype,
    "sink": sink,
    "method_id": method_id,
    "call_ast_id": call_ast_id,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  method := object.get(v, "method", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}