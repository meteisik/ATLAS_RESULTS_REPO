package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file path constructions where the path is built from externally controlled input (e.g., environment variables, request parameters) without validation."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

core_positive_condition(f) if {
  ok := object.get(f, "origin_kinds", [])
  is_array(ok)
  count(ok) > 0
  some kind in ok
  kind != "literal"
  kind != "constant"

  ov := object.get(f, "origin_values", [])
  is_array(ov)
  count(ov) > 0
}

allowed_context(f) if {
  ok := object.get(f, "origin_kinds", [])
  is_array(ok)
  count(ok) > 0
  every kind in ok {
    kind in {"literal", "constant"}
  }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  sink   := object.get(f, "sink_member", "")
  ftype  := object.get(f, "fact_type", "")

  desc := sprintf("Path traversal: file path at %s.%s (line %v) constructed from externally controlled input", [
    cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
  }
]

deny contains msg if {
  v := findings[_]
  cls := object.get(v, "class", "")
  method := object.get(v, "method", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s.%s (line %d)", [
    v.policy_id, v.title, cls, method, line,
  ])
}