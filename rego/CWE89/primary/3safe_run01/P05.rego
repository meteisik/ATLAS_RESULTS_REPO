package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detects SQL queries built from externally controlled input."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f | f := data.drivers.cwe89_facts.facts[_]]

contains_non_literal_kind(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}

contains_getenv(f) if {
  values := object.get(f, "origin_values", [])
  some v in values
  v == "getenv"
}

safe_sql_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

core_positive_condition(f) if {
  f.sink_member == "executeQuery"
  f.sink_node_type == "method_invocation"
  f.sink_resolved_type == "java.sql.Statement"
  contains_non_literal_kind(f)
  contains_getenv(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_sql_literal_only(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)
  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))
  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")
  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
    "classification": "VIOLATION",
    "origin_kinds":   object.get(f, "origin_kinds", []),
    "origin_values":  object.get(f, "origin_values", []),
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