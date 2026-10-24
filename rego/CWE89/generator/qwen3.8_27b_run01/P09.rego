package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detects JDBC query execution where the SQL text is built from externally controlled input."

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
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

  ftype  := object.get(f, "fact_type", "sql_query_fact")
  sink   := object.get(f, "sink_member", "")
  sink_type := object.get(f, "sink_resolved_type", "")
  kinds  := object.get(f, "origin_kinds", [])
  vals   := object.get(f, "origin_values", [])

  desc := sprintf("SQL Injection: %s.%s at line %d, col %d — sink=%s (%s), origin_kinds=%v, origin_values=%v", [
    cls, method, line, col, sink, sink_type, kinds, vals,
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
    "origin_kinds": kinds,
    "origin_values": vals,
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
    "query_arg_ast_id": object.get(f, "query_arg_ast_id", 0),
  }
]

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  cls  := object.get(v, "class", "")
  method := object.get(v, "method", "")
  line := object.get(v, "line", 0)
  col  := object.get(v, "col", 0)
  sink := object.get(v, "sink", "")

  msg := sprintf("[%s] %s: %s.%s at %s:%d:%d (sink=%s)", [
    v.policy_id, v.title, cls, method, file, line, col, sink,
  ])
}