package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f | f := data.drivers.cwe284_facts.facts[_]]

guard_call_present(f) if {
  call_ids := object.get(f, "guard_call_ast_ids", [])
  count(call_ids) > 0
}

guard_subject_has_getenv(f) if {
  vals := object.get(f, "guard_subject_origin_values", [])
  some v in vals
  v == "getenv"
}

guard_sink_in_thenPart(f) if {
  branches := object.get(f, "guard_sink_branches", [])
  count(branches) > 0
  some i
  count(branches) > i
  branches[i] == "thenPart"
}

allowed_context(f) if {
  guard_call_present(f)
  guard_subject_has_getenv(f)
  guard_sink_in_thenPart(f)
}

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  count(kinds) == 1
  count(vals) == 1
  kinds[0] == "call_result"
  vals[0] == "getenv"

  sink_member := object.get(f, "sink_member", "")
  sink_member == "executeUpdate"

  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"

  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "java.sql.PreparedStatement"
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
  sink := object.get(f, "sink", "")

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
    "sink":        sink
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