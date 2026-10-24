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

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  fact_type := object.get(f, "fact_type", "")
  fact_type == "sensitive_operation_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every k in origin_kinds { k == "call_result" }

  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
  every v in origin_values { v == "getProperty" }

  sink_member := object.get(f, "sink_member", "")
  sink_member == "executeUpdate"

  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"

  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "java.sql.PreparedStatement"
}

allowed_context(f) if {
  guard_call_names := object.get(f, "guard_call_names", [])
  guard_call_ast_ids := object.get(f, "guard_call_ast_ids", [])
  guard_condition_ast_ids := object.get(f, "guard_condition_ast_ids", [])
  guard_sink_branches := object.get(f, "guard_sink_branches", [])

  count(guard_call_names) > 0
  count(guard_call_ast_ids) > 0
  count(guard_condition_ast_ids) > 0
  count(guard_sink_branches) > 0

  some i
  guard_call_names[i] == "isAuthorized"
  guard_call_ast_ids[i] = cid

  some j
  guard_condition_ast_ids[j] == cid
  guard_sink_branches[j] == "thenPart"
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
    v.policy_id,
    v.title,
    file,
    line,
  ])
}