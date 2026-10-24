package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects data-modifying statements that execute without a matching authorization guard."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core positive condition: required fields that indicate a violating fact.
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == primary_fact_type
  count(object.get(f, "origin_kinds", [])) > 0
  count(object.get(f, "origin_values", [])) > 0
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
}

# Guard rule: a guard directly encloses the sink (thenPart/elsePart non‑empty).
guard_encloses_sink(f) if {
  some branch in object.get(f, "guard_sink_branches", [])
  branch != ""
}

# Guard rule: a preceding guard exits control flow before the sink (exit edge non‑empty).
preceding_guard_exits_before_sink(f) if {
  some exit in object.get(f, "guard_exit_edges", [])
  exit != ""
}

# Any guard that makes the execution safe.
allowed_context(f) if {
  guard_encloses_sink(f)
}
allowed_context(f) if {
  preceding_guard_exits_before_sink(f)
}

# Violation predicate.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings for each violating fact.
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

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

# Human‑readable deny messages.
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