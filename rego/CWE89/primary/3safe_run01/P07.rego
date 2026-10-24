package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detects SQL queries built from externally controlled input."

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

is_literal_or_unknown(k) if { k == "literal" }
is_literal_or_unknown(k) if { k == "unknown" }

core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sql_query_fact"
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  some k in kinds
  not is_literal_or_unknown(k)
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds { is_literal_or_unknown(k) }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := ""
  line := object.get(f, "line", 0)
  span := {"start": {"line": line}}

  fact_type_val := object.get(f, "fact_type", "")
  method_name := object.get(f, "method_name", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "call_ast_id", 0)

  sink := object.get(f, "sink_member", "")
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "span":        span,
    "fact_type":   fact_type_val,
    "method_name": method_name,
    "method_id":   method_id,
    "call_ast_id": call_ast_id,
    "sink":        sink,
    "sink_node_type": sink_node_type,
    "sink_resolved_type": sink_resolved_type,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  span := object.get(v, "span", {})
  start := object.get(span, "start", {})
  line := object.get(start, "line", 0)
  method := object.get(v, "method_name", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}