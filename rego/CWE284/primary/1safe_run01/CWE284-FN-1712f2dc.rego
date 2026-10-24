package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects data‑modifying JDBC executions that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Helper to check list non-empty and no empty strings
non_empty_no_sentinel(list) := true if {
  count(list) > 0
  every v in list { v != "" }
}

# Core positive condition: facts that potentially violate the policy
core_positive_condition(f) if {
  fact_type := object.get(f, "fact_type", "")
  fact_type == "sensitive_operation_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  non_empty_no_sentinel(origin_kinds)

  origin_values := object.get(f, "origin_values", [])
  non_empty_no_sentinel(origin_values)

  sink_member := object.get(f, "sink_member", "")
  sink_member == "executeUpdate"

  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"

  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "java.sql.PreparedStatement"
}

# Allowed context: safe if any guard-related field is present
allowed_context(f) if {
  guard_call_names := object.get(f, "guard_call_names", [])
  count(guard_call_names) > 0
}
allowed_context(f) if {
  guard_condition_operators := object.get(f, "guard_condition_operators", [])
  count(guard_condition_operators) > 0
}
allowed_context(f) if {
  guard_exit_edges := object.get(f, "guard_exit_edges", [])
  count(guard_exit_edges) > 0
}
allowed_context(f) if {
  guard_sink_branches := object.get(f, "guard_sink_branches", [])
  count(guard_sink_branches) > 0
}
allowed_context(f) if {
  guard_subject_origin_kinds := object.get(f, "guard_subject_origin_kinds", [])
  count(guard_subject_origin_kinds) > 0
}
allowed_context(f) if {
  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  count(guard_subject_origin_values) > 0
}
allowed_context(f) if {
  guard_subject_origin_ast_ids := object.get(f, "guard_subject_origin_ast_ids", [])
  count(guard_subject_origin_ast_ids) > 0
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls  := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := severity
  ftype := object.get(f, "fact_type", "")
  sink := object.get(f, "sink_member", "")

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

# Human‑readable deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}