package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file-system path constructions whose path argument includes a runtime-provided origin (call_result, field, or parameter) without validation."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  some kind in kinds
  kind != "literal"
  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every kind in kinds {
    kind == "literal"
  }
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) == 0
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  col    := object.get(f, "col", 0)
  ftype  := object.get(f, "fact_type", primary_fact_type)
  sink_id := object.get(f, "sink_ast_id", 0)
  sink_member := object.get(f, "sink_member", "")
  sink_resolved := object.get(f, "sink_resolved_type", "")
  path_arg_id := object.get(f, "path_arg_ast_id", 0)
  consumer_id := object.get(f, "file_consumer_ast_id", 0)
  method_id := object.get(f, "method_id", 0)
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])

  desc := sprintf("Path traversal: File constructor at %s.%s (line %v) has runtime-provided path origin %v", [
    cls, method, line, origin_values,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "col":         col,
    "fact_type":   ftype,
    "sink_ast_id": sink_id,
    "sink_member": sink_member,
    "sink_resolved_type": sink_resolved,
    "path_arg_ast_id": path_arg_id,
    "file_consumer_ast_id": consumer_id,
    "method_id":   method_id,
    "origin_kinds": origin_kinds,
    "origin_values": origin_values,
  }
]

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  cls  := object.get(v, "class", "")
  method := object.get(v, "method", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s.%s:%d", [
    v.policy_id, v.title, cls, method, line,
  ])
}