package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sensitive_operation_fact"
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
  object.get(f, "sink_member", "") == "executeUpdate"
}

guard_on_same_subject(f) if {
  guard_subject_origin_kinds := object.get(f, "guard_subject_origin_kinds", [])
  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])
  count(guard_subject_origin_kinds) > 0
  count(origin_kinds) > 0
  some gi
  gi < count(guard_subject_origin_kinds)
  gi < count(origin_kinds)
  guard_subject_origin_kinds[gi] == origin_kinds[gi]
  guard_subject_origin_values[gi] == origin_values[gi]
}

allowed_context(f) if {
  guard_call_names := object.get(f, "guard_call_names", [])
  count(guard_call_names) > 0
  guard_condition_ast_ids := object.get(f, "guard_condition_ast_ids", [])
  count(guard_condition_ast_ids) > 0
  guard_on_same_subject(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name := object.get(f, "method_name", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "call_ast_id", 0)

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