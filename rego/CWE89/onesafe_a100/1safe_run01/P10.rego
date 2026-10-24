package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input."

driver_facts := [f | f := data.drivers.cwe89_facts.facts[_] ]

# Small boolean-field helper
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

# Helper: check if any origin_kind is not literal
has_non_literal_origin(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some kind in origin_kinds
  kind != "literal"
}

# Helper: check if any origin_value is runtime-derived (example getenv)
has_runtime_value(f) if {
  origin_values := object.get(f, "origin_values", [])
  some val in origin_values
  val == "getenv"
}

# core positive condition
core_positive_condition(f) if {
  has_non_literal_origin(f)
}
core_positive_condition(f) if {
  has_runtime_value(f)
}

# Guard: safe only if all origins literal
guard_sql_literal_only(f) if {
  not has_non_literal_origin(f)
}

# Guard: safe executeQuery with literal origins
guard_execute_query_literal(f) if {
  not has_non_literal_origin(f)
  sink_member := object.get(f, "sink_member", "")
  sink_member == "executeQuery"
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "java.sql.Statement"
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_sql_literal_only(f)
  not guard_execute_query_literal(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

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
    "sink":        sink
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}