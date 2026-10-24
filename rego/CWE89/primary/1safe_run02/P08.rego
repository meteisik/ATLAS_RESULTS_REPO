package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# helper: true if all elements are the string "literal"
all_literals(lst) := true if {
  every x in lst { x == "literal" }
}

# guard: safe when the sink is a JDBC execute method and all origins are literal
guard_statement_execute_query(f) if {
  member := object.get(f, "sink_member", "")
  member == "executeQuery"

  node_type := object.get(f, "sink_node_type", "")
  node_type == "method_invocation"

  resolved_type := object.get(f, "sink_resolved_type", "")
  resolved_type == "java.sql.Statement"

  kinds := object.get(f, "origin_kinds", [])
  all_literals(kinds)
}

# core positive condition: at least one origin kind is non‑literal
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}

# violation if core condition holds and guard does not
is_violation(f) if {
  core_positive_condition(f)
  not guard_statement_execute_query(f)
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

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": desc,

    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
  }
]

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}