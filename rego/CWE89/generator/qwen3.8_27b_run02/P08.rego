package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detects JDBC query execution sites whose SQL text argument is built from externally controlled (runtime-provided) input rather than solely from literal constants."

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

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

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  col    := object.get(f, "col", 0)
  sink   := object.get(f, "sink_member", "")
  sink_type := object.get(f, "sink_resolved_type", "")
  ftype  := object.get(f, "fact_type", "sql_query_fact")
  sink_id := object.get(f, "sink_ast_id", 0)
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])
  receiver_name := object.get(f, "receiver_decl_name", "")

  desc := sprintf("SQL injection: %s.%s at line %v — SQL text for %s.%s includes runtime-provided origin(s): %v", [
    cls, method, line, sink_type, sink, origin_values,
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
    "sink":        sink,
    "sink_resolved_type": sink_type,
    "sink_ast_id": sink_id,
    "origin_kinds": origin_kinds,
    "origin_values": origin_values,
    "receiver_decl_name": receiver_name,
  }
]

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  cls  := object.get(v, "class", "")
  method := object.get(v, "method", "")
  sink := object.get(v, "sink", "")
  origin_values := object.get(v, "origin_values", [])

  msg := sprintf("[%s] %s: %s.%s at %s:%d — sink=%s, runtime origins=%v", [
    v.policy_id, v.title, cls, method, file, line, sink, origin_values,
  ])
}