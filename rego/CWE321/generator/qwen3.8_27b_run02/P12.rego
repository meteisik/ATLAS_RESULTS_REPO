package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects cryptographic key material whose provenance is entirely compile-time fixed literals."

primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

is_violation(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every k in kinds { k == "literal" }

  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  col    := object.get(f, "col", 0)
  sink   := object.get(f, "sink_member", "")
  ftype  := object.get(f, "fact_type", "crypto_key_material_fact")
  algo   := object.get(f, "algorithm", "")

  desc := sprintf("Hard-coded cryptographic key in %s.%s (line %v): key material derived entirely from literal origin(s) %v", [
    cls, method, line, object.get(f, "origin_values", []),
  ])

  finding := {
    "policy_id":     policy_id,
    "title":         title,
    "severity":      severity,
    "description":   desc,
    "class":         cls,
    "method":        method,
    "line":          line,
    "col":           col,
    "fact_type":     ftype,
    "sink":          sink,
    "algorithm":     algo,
    "sink_ast_id":   object.get(f, "sink_ast_id", 0),
    "origin_kinds":  object.get(f, "origin_kinds", []),
    "origin_values": object.get(f, "origin_values", []),
  }
]

deny contains msg if {
  v := findings[_]

  cls    := object.get(v, "class", "")
  method := object.get(v, "method", "")
  line   := object.get(v, "line", 0)

  msg := sprintf("[%s] %s in %s.%s at line %d: %s", [
    v.policy_id, v.title, cls, method, line, v.description,
  ])
}