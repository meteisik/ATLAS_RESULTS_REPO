package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_key := "cwe284_facts"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core violation logic
core_positive_condition(f) if {
  # All guard-related fields must be empty
  count(object.get(f, "guard_call_names", [])) == 0
  count(object.get(f, "guard_condition_operators", [])) == 0
  count(object.get(f, "guard_exit_edges", [])) == 0
  count(object.get(f, "guard_sink_branches", [])) == 0
  count(object.get(f, "guard_subject_origin_kinds", [])) == 0
  count(object.get(f, "guard_subject_origin_values", [])) == 0

  # Origin lists must contain non‑sentinel values
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
}

# Safe contexts when any guard field is populated
allowed_context(f) if {
  count(object.get(f, "guard_call_names", [])) > 0
}
allowed_context(f) if {
  count(object.get(f, "guard_condition_operators", [])) > 0
}
allowed_context(f) if {
  count(object.get(f, "guard_exit_edges", [])) > 0
}
allowed_context(f) if {
  count(object.get(f, "guard_sink_branches", [])) > 0
}
allowed_context(f) if {
  count(object.get(f, "guard_subject_origin_kinds", [])) > 0
}
allowed_context(f) if {
  count(object.get(f, "guard_subject_origin_values", [])) > 0
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink_member", "")

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": description,
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
  method := object.get(v, "method", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}