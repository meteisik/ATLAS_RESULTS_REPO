package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f | f := data.drivers.cwe284_facts.facts[_]]

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) == 1
  kinds[0] == "call_result"

  vals := object.get(f, "origin_values", [])
  count(vals) == 1
  vals[0] == "getenv"

  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
}

guard_call_ast_ids_guard(f) if {
  guard := object.get(f, "guard_call_ast_ids", [])
  count(guard) > 0
}
guard_call_names_guard(f) if {
  guard := object.get(f, "guard_call_names", [])
  count(guard) > 0
}
guard_condition_ast_ids_guard(f) if {
  guard := object.get(f, "guard_condition_ast_ids", [])
  count(guard) > 0
}
guard_condition_operators_guard(f) if {
  guard := object.get(f, "guard_condition_operators", [])
  count(guard) > 0
}
guard_exit_edges_guard(f) if {
  guard := object.get(f, "guard_exit_edges", [])
  count(guard) > 0
}
guard_sink_branches_guard(f) if {
  guard := object.get(f, "guard_sink_branches", [])
  count(guard) > 0
}
guard_subject_origin_ast_ids_guard(f) if {
  guard := object.get(f, "guard_subject_origin_ast_ids", [])
  count(guard) > 0
}
guard_subject_origin_kinds_guard(f) if {
  guard := object.get(f, "guard_subject_origin_kinds", [])
  count(guard) > 0
}
guard_subject_origin_values_guard(f) if {
  guard := object.get(f, "guard_subject_origin_values", [])
  count(guard) > 0
}

guarded(f) if {
  guard_call_ast_ids_guard(f)
}
guarded(f) if {
  guard_call_names_guard(f)
}
guarded(f) if {
  guard_condition_ast_ids_guard(f)
}
guarded(f) if {
  guard_condition_operators_guard(f)
}
guarded(f) if {
  guard_exit_edges_guard(f)
}
guarded(f) if {
  guard_sink_branches_guard(f)
}
guarded(f) if {
  guard_subject_origin_ast_ids_guard(f)
}
guarded(f) if {
  guard_subject_origin_kinds_guard(f)
}
guarded(f) if {
  guard_subject_origin_values_guard(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not guarded(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := severity
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