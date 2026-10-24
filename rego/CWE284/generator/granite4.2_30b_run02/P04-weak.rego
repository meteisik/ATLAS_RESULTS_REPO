package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

primary_fact_type := "sensitive_operation_fact"

sink_matches(f) if {
  node_type := object.get(f, "sink_node_type", "")
  resolved_type := object.get(f, "sink_resolved_type", "")
  member := object.get(f, "sink_member", "")
  node_type == "method_invocation"
  resolved_type == "java.sql.PreparedStatement"
  member == "executeUpdate"
}

guard_present(f) if {
  gcids := object.get(f, "guard_condition_ast_ids", [])
  gcallids := object.get(f, "guard_call_ast_ids", [])
  gsoids := object.get(f, "guard_subject_origin_ast_ids", [])
  count(gcids) > 0
  count(gcallids) > 0
  count(gsoids) > 0
}

unguarded(f) if {
  gcids := object.get(f, "guard_condition_ast_ids", [])
  gcallids := object.get(f, "guard_call_ast_ids", [])
  gsoids := object.get(f, "guard_subject_origin_ast_ids", [])
  gcids == []
  gcallids == []
  gsoids == []
}

aligned(f) if {
  object.get(f, "guard_subject_origin_ast_ids", []) == object.get(f, "origin_ast_ids", [])
}

discriminator_ok(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  kinds == ["call_result"]
  values == ["getenv"]
}

core_positive_condition(f) if {
  sink_matches(f)
  discriminator_ok(f)
  unguarded(f)
}

core_positive_condition(f) if {
  sink_matches(f)
  discriminator_ok(f)
  guard_present(f)
  not aligned(f)
}

allowed_context(f) if {
  sink_matches(f)
  guard_present(f)
  aligned(f)
  sink_branches := object.get(f, "guard_sink_branches", [])
  count(sink_branches) > 0
  sink_branches[0] == "thenPart"
}

allowed_context(f) if {
  sink_matches(f)
  guard_present(f)
  aligned(f)
  sink_branches := object.get(f, "guard_sink_branches", [])
  sink_branches == []
  exit_edges := object.get(f, "guard_exit_edges", [])
  count(exit_edges) > 0
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))
  span_raw := object.get(f, "span", {"start": {"line": line}})

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