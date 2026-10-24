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

# Safe query guard: all origins are literal
guard_literal_only_sql(f) if {
  every k in object.get(f, "origin_kinds", []) { not k != "literal" }
}

# Violation condition: at least one non‑literal origin
core_positive_condition(f) if {
  k_list := object.get(f, "origin_kinds", [])
  some k in k_list
  k != "literal"
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_literal_only_sql(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := ""
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev   := severity
  ftype := object.get(f, "fact_type", "")
  sink  := object.get(f, "sink_member", "")

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
  }
]

deny contains msg if {
  v := findings[_]
  file   := object.get(v, "file", "")
  line   := object.get(v, "line", 0)
  method := object.get(v, "method", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method
  ])
}