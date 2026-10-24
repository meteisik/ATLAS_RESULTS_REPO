package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects data‑modifying JDBC executions that run without a matching authorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Helper to check non-empty list
non_empty_list(l) := true if {
  count(l) > 0
}

# Core positive condition: every violating fact has origin_kinds and origin_values non-empty,
# and all guard-related fields empty
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  non_empty_list(origin_kinds)

  origin_values := object.get(f, "origin_values", [])
  non_empty_list(origin_values)

  guard_call_names := object.get(f, "guard_call_names", [])
  count(guard_call_names) == 0

  guard_condition_operators := object.get(f, "guard_condition_operators", [])
  count(guard_condition_operators) == 0

  guard_exit_edges := object.get(f, "guard_exit_edges", [])
  count(guard_exit_edges) == 0

  guard_sink_branches := object.get(f, "guard_sink_branches", [])
  count(guard_sink_branches) == 0

  guard_subject_origin_kinds := object.get(f, "guard_subject_origin_kinds", [])
  count(guard_subject_origin_kinds) == 0

  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  count(guard_subject_origin_values) == 0
}

# Safe contexts are not considered violations.  All facts that pass the
# core_positive_condition are violations; no additional filtering is required.
allowed_context(f) if {
  false
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

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
    v.policy_id, v.title, file, line,
  ])
}