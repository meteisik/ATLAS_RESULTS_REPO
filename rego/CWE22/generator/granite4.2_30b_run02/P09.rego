package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_facts := [f | f := data.drivers.cwe22_facts.facts[_]]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

core_positive_condition(f) if {
  node_type := object.get(f, "sink_node_type", "")
  resolved_type := object.get(f, "sink_resolved_type", "")
  member := object.get(f, "sink_member", "")
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])

  node_type == "class_creator"
  resolved_type == "java.io.File"
  member == "File"
  count(kinds) > 0
  count(values) > 0
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every kind in kinds {
    kind == "literal"
  }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name := object.get(f, "method_name", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "call_ast_id", 0)

  sink := object.get(f, "sink", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,

    "file":        file_raw,
    "span":        span_raw,

    "fact_type":   fact_type_val,
    "method_name": method_name,
    "method_id":   method_id,
    "call_ast_id": call_ast_id,

    "sink":        sink,
  }
]

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  span := object.get(v, "span", {})
  start := object.get(span, "start", {})
  line := object.get(start, "line", 0)
  method := object.get(v, "method_name", "")

  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}