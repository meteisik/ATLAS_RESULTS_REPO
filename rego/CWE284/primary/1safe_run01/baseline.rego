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

# Core positive condition: facts of type sensitive_operation_fact whose origin is a call_result of getenv
core_positive_condition(f) if {
  fact_type := object.get(f, "fact_type", "")
  fact_type == "sensitive_operation_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  origin_kinds == ["call_result"]

  origin_values := object.get(f, "origin_values", [])
  origin_values == ["getenv"]
}

# Guard rule: a safe execution must be guarded by an isAuthorized check that encloses the sink
safe_isAuthorized_guard(f) if {
  guard_call_names := object.get(f, "guard_call_names", [])
  some v in guard_call_names
  v == "isAuthorized"

  guard_condition_ast_ids := object.get(f, "guard_condition_ast_ids", [])
  count(guard_condition_ast_ids) > 0

  guard_sink_branches := object.get(f, "guard_sink_branches", [])
  some w in guard_sink_branches
  w == "thenPart"

  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  some u in guard_subject_origin_values
  u == "getenv"
}

allowed_context(f) if {
  safe_isAuthorized_guard(f)
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

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
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