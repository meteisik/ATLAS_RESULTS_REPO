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

# Core detection: a runtime origin present
core_positive_condition(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind == "call_result"
}
core_positive_condition(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind == "parameter"
}
core_positive_condition(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind == "field"
}
core_positive_condition(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind == "unknown"
}

# Safe contexts: all origins are literals
allowed_context(f) if {
  every kind in object.get(f, "origin_kinds", []) { kind == "literal" }
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

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
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
    v.policy_id,
    v.title,
    file,
    line,
  ])
}