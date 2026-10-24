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
  object.get(f, "fact_type", "") == "sensitive_operation_fact"
  object.get(f, "origin_kinds", []) == ["call_result"]
  object.get(f, "origin_values", []) == ["getenv"]
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
  object.get(f, "guard_call_ast_ids", []) == []
  object.get(f, "guard_call_names", []) == []
  object.get(f, "guard_condition_ast_ids", []) == []
  object.get(f, "guard_condition_operators", []) == []
  object.get(f, "guard_exit_edges", []) == []
  object.get(f, "guard_sink_branches", []) == []
  object.get(f, "guard_subject_origin_ast_ids", []) == []
  object.get(f, "guard_subject_origin_kinds", []) == []
  object.get(f, "guard_subject_origin_values", []) == []
}

guard_has_call(f) if {
  guard_call_ast_ids := object.get(f, "guard_call_ast_ids", [])
  guard_call_names := object.get(f, "guard_call_names", [])
  count(guard_call_ast_ids) > 0
  count(guard_call_names) > 0
}

guard_nonempty_condition_ast_ids(f) if {
  guard_condition_ast_ids := object.get(f, "guard_condition_ast_ids", [])
  count(guard_condition_ast_ids) > 0
}

guard_nonempty_condition_operators(f) if {
  guard_condition_operators := object.get(f, "guard_condition_operators", [])
  count(guard_condition_operators) > 0
}

guard_nonempty_exit_edges(f) if {
  guard_exit_edges := object.get(f, "guard_exit_edges", [])
  count(guard_exit_edges) > 0
}

guard_nonempty_sink_branches(f) if {
  guard_sink_branches := object.get(f, "guard_sink_branches", [])
  count(guard_sink_branches) > 0
}

guard_nonempty_subject_origin_ast_ids(f) if {
  guard_subject_origin_ast_ids := object.get(f, "guard_subject_origin_ast_ids", [])
  count(guard_subject_origin_ast_ids) > 0
}

guard_nonempty_subject_origin_kinds(f) if {
  guard_subject_origin_kinds := object.get(f, "guard_subject_origin_kinds", [])
  count(guard_subject_origin_kinds) > 0
}

guard_nonempty_subject_origin_values(f) if {
  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  count(guard_subject_origin_values) > 0
}

allowed_context(f) if {
  guard_has_call(f)
  guard_nonempty_condition_ast_ids(f)
  guard_nonempty_condition_operators(f)
  guard_nonempty_exit_edges(f)
  guard_nonempty_sink_branches(f)
  guard_nonempty_subject_origin_ast_ids(f)
  guard_nonempty_subject_origin_kinds(f)
  guard_nonempty_subject_origin_values(f)
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