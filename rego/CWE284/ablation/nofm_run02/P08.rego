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
  object.get(f, "fact_type", "") == "sensitive_operation_fact"
  ks := object.get(f, "origin_kinds", [])
  ks == ["call_result"]
  vs := object.get(f, "origin_values", [])
  vs == ["getenv"]
  sm := object.get(f, "sink_member", "")
  sm == "executeUpdate"
  sn := object.get(f, "sink_node_type", "")
  sn == "method_invocation"
  sr := object.get(f, "sink_resolved_type", "")
  sr == "java.sql.PreparedStatement"
}

allowed_context(f) if {
  subject_kinds := object.get(f, "guard_subject_origin_kinds", [])
  subject_vals := object.get(f, "guard_subject_origin_values", [])
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  subject_kinds == ks
  subject_vals == vs
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := severity
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": desc,
    "file":        file,
    "span":        object.get(f, "span", {"start": {"line": line}}),
    "fact_type":   ftype,
    "method_name": method,
    "method_id":   object.get(f, "method_id", 0),
    "call_ast_id": 0,
    "sink":        sink,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  method := object.get(v, "method_name", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}