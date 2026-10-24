package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

# List of facts emitted by the driver.
driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core condition that identifies a potentially violating execution.
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sensitive_operation_fact"
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"

  ok_kinds := object.get(f, "origin_kinds", [])
  count(ok_kinds) == 1
  ok_kinds[0] == "call_result"

  ok_vals := object.get(f, "origin_values", [])
  count(ok_vals) == 1
  ok_vals[0] == "getenv"

  guard_cond := object.get(f, "guard_condition_ast_ids", [])
  count(guard_cond) == 0

  guard_br := object.get(f, "guard_sink_branches", [])
  count(guard_br) == 0

  guard_exit := object.get(f, "guard_exit_edges", [])
  count(guard_exit) == 0
}

# Guard presence rules – any non‑empty guard array indicates a safe execution.
guard_present_condition_ids(f) if {
  ids := object.get(f, "guard_condition_ast_ids", [])
  count(ids) > 0
}

guard_present_sink_branch(f) if {
  br := object.get(f, "guard_sink_branches", [])
  count(br) > 0
}

guard_present_exit_edge(f) if {
  ex := object.get(f, "guard_exit_edges", [])
  count(ex) > 0
}

# An allowed (safe) context is any fact that has a guard recorded.
allowed_context(f) if {
  guard_present_condition_ids(f)
}
allowed_context(f) if {
  guard_present_sink_branch(f)
}
allowed_context(f) if {
  guard_present_exit_edge(f)
}

# Violation predicate: matches core condition and is not in an allowed context.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: normalized representation of each violation.
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

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

# Human‑readable deny messages.
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