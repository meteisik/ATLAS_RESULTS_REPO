package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into\nit, and the authorization decisions that decide whether it runs, so the\npolicy layer can detect sensitive operations that run without a matching\nauthorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core violation logic: a fact is a violation if all guard-related and origin-related fields are empty.
core_positive_condition(f) if {
  guard_calls := object.get(f, "guard_call_ast_ids", [])
  guard_cond  := object.get(f, "guard_condition_ast_ids", [])
  guard_subj  := object.get(f, "guard_subject_origin_ast_ids", [])
  origin_ids  := object.get(f, "origin_ast_ids", [])
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_vals  := object.get(f, "origin_values", [])
  count(guard_calls) == 0
  count(guard_cond) == 0
  count(guard_subj) == 0
  count(origin_ids) == 0
  count(origin_kinds) == 0
  count(origin_vals) == 0
}

is_violation(f) if {
  core_positive_condition(f)
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
    "span":        object.get(f, "span", {"start": {"line": line}}),

    "fact_type":   ftype,
    "method_name": method,
    "method_id":   object.get(f, "method_id", 0),
    "call_ast_id": object.get(f, "sink_ast_id", 0),

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