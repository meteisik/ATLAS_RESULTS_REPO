package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detect SQL queries that incorporate runtime‑provided values, indicating potential SQL injection."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind == "call_result"
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds {
    k == "literal"
  }
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

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,

    "file":   file,
    "class":  cls,
    "method": method,
    "line":   line,

    "fact_type": object.get(f, "fact_type", ""),
    "sink":      object.get(f, "sink", ""),
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