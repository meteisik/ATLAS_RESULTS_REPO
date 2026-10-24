package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detect SQL statements whose text is built from runtime‑derived input (environment reads, request parameters, etc.) rather than being composed solely of compile‑time literals."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k == "call_result"
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  ftype := object.get(f, "fact_type", "")
  sink := object.get(f, "sink_member", "")

  v := {
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
    "sink_ast_id":          object.get(f, "sink_ast_id", 0),
    "method_id":            object.get(f, "method_id", 0),
    "receiver_decl_name":   object.get(f, "receiver_decl_name", ""),
    "query_arg_ast_id":     object.get(f, "query_arg_ast_id", 0),
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