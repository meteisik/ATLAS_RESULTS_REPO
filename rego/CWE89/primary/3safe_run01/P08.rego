package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detects SQL queries built from externally controlled input."

# Driver facts list
driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

#
# Guard: safe SQL facts have all origin_kinds == "literal"
#
safe_sql_fact_guard(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

#
# Core positive condition: fact_type must be sql_query_fact and at least one origin_kind is not "literal"
#
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sql_query_fact"
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  some k in kinds
  k != "literal"
}

#
# Violation: core condition holds and the fact is not safe
#
is_violation(f) if {
  core_positive_condition(f)
  not safe_sql_fact_guard(f)
}

#
# Findings: normalize violating facts
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")
  sink_member      := object.get(f, "sink_member", "")
  sink_node_type   := object.get(f, "sink_node_type", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")

  finding := {
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
    "sink_member": sink_member,
    "sink_node_type": sink_node_type,
    "sink_resolved_type": sink_resolved_type,

    "classification": "VIOLATION",
    "origin_kinds":   object.get(f, "origin_kinds", []),
    "origin_values":  object.get(f, "origin_values", []),
  }
]

#
# Deny: human-readable messages for each finding
#
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