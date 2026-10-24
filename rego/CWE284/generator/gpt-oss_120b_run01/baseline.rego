package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

core_positive_condition(f) if {
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"

  ok_kinds := object.get(f, "origin_kinds", [])
  count(ok_kinds) == 1
  ok_kinds[0] == "call_result"

  ok_vals := object.get(f, "origin_values", [])
  count(ok_vals) == 1
  ok_vals[0] == "getenv"
}

guard_subject_match(f) if {
  origin_ids := object.get(f, "origin_ast_ids", [])
  guard_ids := object.get(f, "guard_subject_origin_ast_ids", [])
  count(origin_ids) > 0
  count(guard_ids) > 0
  some oid in origin_ids
  some gid in guard_ids
  oid == gid

  origin_kinds := object.get(f, "origin_kinds", [])
  guard_kinds := object.get(f, "guard_subject_origin_kinds", [])
  count(origin_kinds) > 0
  count(guard_kinds) > 0
  some ok in origin_kinds
  some gk in guard_kinds
  ok == gk

  origin_vals := object.get(f, "origin_values", [])
  guard_vals := object.get(f, "guard_subject_origin_values", [])
  count(origin_vals) > 0
  count(guard_vals) > 0
  some ov in origin_vals
  some gv in guard_vals
  ov == gv
}

allowed_context(f) if {
  guard_subject_match(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

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