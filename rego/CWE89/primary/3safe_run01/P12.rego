package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detects SQL queries built from externally controlled input."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

#
# Core violation logic
#
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sql_query_fact"

  object.get(f, "sink_member", "") == "executeQuery"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.Statement"

  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0

  values := object.get(f, "origin_values", [])
  count(values) > 0
}

#
# Safe context: all origins are literals
#
all_literal_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

allowed_context(f) if {
  all_literal_kinds(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# findings: normalize violating facts into a standard structure
#
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", 0)

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
    "origin_values":  object.get(f, "origin_values", [])
  }
]

#
# deny: human-readable messages for each finding
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id,
    v.title,
    file,
    line
  ])
}