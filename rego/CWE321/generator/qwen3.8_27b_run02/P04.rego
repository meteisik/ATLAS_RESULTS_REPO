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
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  sink_type := object.get(f, "sink_resolved_type", "")
  sink_type != ""

  sink_node := object.get(f, "sink_node_type", "")
  sink_node != ""

  sink_mem := object.get(f, "sink_member", "")
  sink_mem != ""

  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every k in kinds { k in {"literal", "constant"} }

  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  some k in kinds
  k != "literal"
  k != "constant"
}

allowed_context(f) if {
  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) == 0
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) == 0
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
  sinkid := object.get(f, "sink_ast_id", 0)
  kinds  := object.get(f, "origin_kinds", [])
  vals   := object.get(f, "origin_values", [])
  stype  := object.get(f, "sink_resolved_type", "")
  snode  := object.get(f, "sink_node_type", "")

  desc := sprintf("Hard-coded cryptographic key in %s.%s (line %v): key material derived entirely from literal origin(s) %v", [
    cls, method, line, vals,
  ])

  finding := {
    "policy_id":          policy_id,
    "title":              title,
    "severity":           severity,
    "description":        desc,
    "class":              cls,
    "method":             method,
    "line":               line,
    "col":                col,
    "fact_type":          ftype,
    "sink":               sink,
    "algorithm":          algo,
    "sink_ast_id":        sinkid,
    "origin_kinds":       kinds,
    "origin_values":      vals,
    "sink_resolved_type": stype,
    "sink_node_type":     snode,
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