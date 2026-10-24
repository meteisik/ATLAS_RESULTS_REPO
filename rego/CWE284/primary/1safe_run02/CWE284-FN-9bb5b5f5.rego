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

safe_guard(f) if {
  gs := object.get(f, "guard_sink_branches", [])
  gs[_] == "thenPart"
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})
  method := object.get(f, "method_name", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "sink_ast_id", 0)
  sink := object.get(f, "sink_member", "")

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file_raw,
    "span":        span_raw,
    "fact_type":   object.get(f, "fact_type", object.get(f, "kind", "")),
    "method_name": method,
    "method_id":   method_id,
    "call_ast_id": call_ast_id,
    "sink":        sink,
    "line":        line,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}