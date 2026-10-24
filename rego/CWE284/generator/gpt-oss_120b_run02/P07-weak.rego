package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core condition: fact must have the expected origin kind/value and be the correct fact type.
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sensitive_operation_fact"
  object.get(f, "origin_kinds", []) == ["call_result"]
  object.get(f, "origin_values", []) == ["getenv"]
}

# Any non‑empty guard‑related array indicates a safe (allowed) context.
allowed_context(f) if {
  some _ in object.get(f, "guard_condition_ast_ids", [])
}
allowed_context(f) if {
  some _ in object.get(f, "guard_condition_operators", [])
}
allowed_context(f) if {
  some _ in object.get(f, "guard_exit_edges", [])
}
allowed_context(f) if {
  some _ in object.get(f, "guard_sink_branches", [])
}
allowed_context(f) if {
  some _ in object.get(f, "guard_call_ast_ids", [])
}
allowed_context(f) if {
  some _ in object.get(f, "guard_subject_origin_ast_ids", [])
}

# Violation predicate.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

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

    "file":   file,
    "class":  cls,
    "method": method,
    "line":   line,

    "fact_type": object.get(f, "fact_type", ""),
    "sink":      object.get(f, "sink", "")
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