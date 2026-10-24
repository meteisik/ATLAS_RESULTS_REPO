package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

# Driver key this policy consumes facts from.
driver_key := "cwe284_facts"

# Canonical fact list for this policy
driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Helper: true when guard subject origin values match the operation's origin values
guard_subject_matches_operation(f) if {
  subject_vals := object.get(f, "guard_subject_origin_values", [])
  op_vals := object.get(f, "origin_values", [])
  subject_vals == op_vals
}

# Core violation logic: detect potentially unsafe executions
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_kinds == ["call_result"]
  origin_values := object.get(f, "origin_values", [])
  origin_values == ["getenv"]

  guard_call_ast_ids := object.get(f, "guard_call_ast_ids", [])
  count(guard_call_ast_ids) == 0
}

core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_kinds == ["call_result"]
  origin_values := object.get(f, "origin_values", [])
  origin_values == ["getenv"]

  guard_call_ast_ids := object.get(f, "guard_call_ast_ids", [])
  count(guard_call_ast_ids) > 0
  not guard_subject_matches_operation(f)
}

# Safe context: guard call is isAuthorized and guard subject matches operation
allowed_context(f) if {
  guard_call_names := object.get(f, "guard_call_names", [])
  some name in guard_call_names
  name == "isAuthorized"

  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  guard_subject_origin_values == object.get(f, "origin_values", [])
}

# Determine violation
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: normalize violating facts into a standard structure
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line     := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name   := object.get(f, "method_name", "")
  method_id     := object.get(f, "method_id", 0)
  call_ast_id   := object.get(f, "call_ast_id", 0)

  sink := object.get(f, "sink", "")

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,

    "file":        file_raw,
    "span":        span_raw,

    "fact_type":   fact_type_val,
    "method_name": method_name,
    "method_id":   method_id,
    "call_ast_id": call_ast_id,

    "sink":        sink,
  }
]

# Deny: human-readable messages for each finding
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