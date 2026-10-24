package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects cryptographic key material constructed exclusively from compile-time fixed literal values."

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
}

core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "crypto_key_material_fact"
  ok := object.get(f, "origin_kinds", [])
  is_array(ok)
  count(ok) > 0
  every kind in ok {
    kind in {"literal", "constant"}
  }
  ov := object.get(f, "origin_values", [])
  is_array(ov)
  count(ov) > 0
  some val in ov
  val != ""
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)
  sink_member := object.get(f, "sink_member", "")
  algorithm := object.get(f, "algorithm", "")
  origin_values := object.get(f, "origin_values", [])
  origin_kinds := object.get(f, "origin_kinds", [])
  sink_ast_id := object.get(f, "sink_ast_id", 0)
  key_material_decl_name := object.get(f, "key_material_decl_name", "")

  desc := sprintf("Hard-coded cryptographic key for algorithm %s in %s.%s (line %v)", [
    algorithm, cls, method, line,
  ])

  finding := {
    "policy_id": policy_id,
    "title": title,
    "severity": severity,
    "description": desc,
    "class": cls,
    "method": method,
    "line": line,
    "sink_member": sink_member,
    "algorithm": algorithm,
    "origin_kinds": origin_kinds,
    "origin_values": origin_values,
    "sink_ast_id": sink_ast_id,
    "key_material_decl_name": key_material_decl_name,
  }
]

deny contains msg if {
  v := findings[_]
  cls := object.get(v, "class", "")
  method := object.get(v, "method", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s.%s:%d", [
    v.policy_id, v.title, cls, method, line,
  ])
}