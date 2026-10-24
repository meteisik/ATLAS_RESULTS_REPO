package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

core_positive_condition(f) if {
  binding := object.get(f, "binding_call_ast_ids", [])
  count(binding) > 0
}
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(values) > 0
}

allowed_context(f) if {
  cond := object.get(f, "guard_condition_ast_ids", [])
  count(cond) > 0
}
allowed_context(f) if {
  call := object.get(f, "guard_call_ast_ids", [])
  count(call) > 0
}
allowed_context(f) if {
  ops := object.get(f, "guard_condition_operators", [])
  count(ops) > 0
}
allowed_context(f) if {
  exits := object.get(f, "guard_exit_edges", [])
  count(exits) > 0
}
allowed_context(f) if {
  branches := object.get(f, "guard_sink_branches", [])
  count(branches) > 0
}
allowed_context(f) if {
  subj_kinds := object.get(f, "guard_subject_origin_kinds", [])
  count(subj_kinds) > 0
}
allowed_context(f) if {
  subj_vals := object.get(f, "guard_subject_origin_values", [])
  count(subj_vals) > 0
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)
  span := object.get(f, "span", {"start": {"line": line}})
  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name := object.get(f, "method_name", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "call_ast_id", 0)
  sink := object.get(f, "sink_member", "")

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