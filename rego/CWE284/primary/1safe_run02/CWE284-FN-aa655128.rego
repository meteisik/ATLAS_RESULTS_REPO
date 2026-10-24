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
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_kinds == ["call_result"]
  origin_values := object.get(f, "origin_values", [])
  origin_values == ["getenv"]
  sink_member := object.get(f, "sink_member", "")
  sink_member == "executeUpdate"
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "java.sql.PreparedStatement"
}

guard_on_origin_kinds_and_values(f) if {
  guard_call_names := object.get(f, "guard_call_names", [])
  count(guard_call_names) > 0
  guard_call_ast_ids := object.get(f, "guard_call_ast_ids", [])
  count(guard_call_ast_ids) > 0
  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  origin_values := object.get(f, "origin_values", [])
  guard_subject_origin_values == origin_values
  guard_subject_origin_kinds := object.get(f, "guard_subject_origin_kinds", [])
  origin_kinds := object.get(f, "origin_kinds", [])
  guard_subject_origin_kinds == origin_kinds
}

guard_on_binding_calls(f) if {
  binding_call_ast_ids := object.get(f, "binding_call_ast_ids", [])
  count(binding_call_ast_ids) > 0
  guard_condition_ast_ids := object.get(f, "guard_condition_ast_ids", [])
  count(guard_condition_ast_ids) > 0
  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  origin_values := object.get(f, "origin_values", [])
  guard_subject_origin_values == origin_values
  guard_subject_origin_kinds := object.get(f, "guard_subject_origin_kinds", [])
  origin_kinds := object.get(f, "origin_kinds", [])
  guard_subject_origin_kinds == origin_kinds
}

allowed_context(f) if {
  guard_on_origin_kinds_and_values(f)
}
allowed_context(f) if {
  guard_on_binding_calls(f)
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
  sink   := object.get(f, "sink", "")

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