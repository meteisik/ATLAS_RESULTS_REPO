package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Helper: check if guard subject origins align with operation origins
guard_call_subject_origin_aligned(f) if {
  guard_call_ids := object.get(f, "guard_call_ast_ids", [])
  count(guard_call_ids) > 0
  guard_subj_ids := object.get(f, "guard_subject_origin_ast_ids", [])
  count(guard_subj_ids) > 0
  origins := object.get(f, "origin_ast_ids", [])
  every g in guard_subj_ids {
    some o in origins
    o == g
  }
}

# Rule 1: Unguarded execution (empty guard_call_ast_ids) with required constants
core_positive_condition(f) if {
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_member := object.get(f, "sink_member", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  origins := object.get(f, "origin_ast_ids", [])
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  guard_call_ids := object.get(f, "guard_call_ast_ids", [])

  sink_node_type == "method_invocation"
  sink_member == "executeUpdate"
  sink_resolved_type == "java.sql.PreparedStatement"
  count(origins) > 0
  kinds == ["call_result"]
  values == ["getenv"]
  count(guard_call_ids) == 0
}

# Rule 2: Guarded execution with misaligned subject origins and required constants
core_positive_condition(f) if {
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_member := object.get(f, "sink_member", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  origins := object.get(f, "origin_ast_ids", [])
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  guard_call_ids := object.get(f, "guard_call_ast_ids", [])

  sink_node_type == "method_invocation"
  sink_member == "executeUpdate"
  sink_resolved_type == "java.sql.PreparedStatement"
  count(origins) > 0
  kinds == ["call_result"]
  values == ["getenv"]
  count(guard_call_ids) > 0
  not guard_call_subject_origin_aligned(f)
}

allowed_context(f) if {
  guard_call_subject_origin_aligned(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  sev := object.get(f, "severity", "HIGH")
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
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