package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects data-modifying statements that execute without a matching authorization guard."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

core_positive_condition(f) if {
  object.get(f, "origin_kinds", []) == ["call_result"]
  object.get(f, "origin_values", []) == ["getenv"]
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
}

allowed_context(f) if {
  guard_sink_branches := object.get(f, "guard_sink_branches", [])
  guard_exit_edges := object.get(f, "guard_exit_edges", [])
  guard_condition_operators := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guard_sink_branches)
  guard_sink_branches[i] == "thenPart"
  guard_exit_edges[i] == ""
  guard_condition_operators[i] == ""
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

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink", "")
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