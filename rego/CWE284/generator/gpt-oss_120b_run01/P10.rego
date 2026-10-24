package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core positive condition per committed policy plan
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "sensitive_operation_fact"

  okinds := object.get(f, "origin_kinds", [])
  count(okinds) == 1
  okinds[0] == "call_result"

  ovals := object.get(f, "origin_values", [])
  count(ovals) == 1
  ovals[0] == "getenv"

  guard_cond := object.get(f, "guard_condition_ast_ids", [])
  count(guard_cond) == 0

  guard_call := object.get(f, "guard_call_ast_ids", [])
  count(guard_call) == 0

  guard_names := object.get(f, "guard_call_names", [])
  count(guard_names) == 0

  guard_sub_ast := object.get(f, "guard_subject_origin_ast_ids", [])
  count(guard_sub_ast) == 0

  guard_sub_kinds := object.get(f, "guard_subject_origin_kinds", [])
  count(guard_sub_kinds) == 0

  guard_sub_vals := object.get(f, "guard_subject_origin_values", [])
  count(guard_sub_vals) == 0
}

# Guard presence indicates a safe context (at least one recorded guard condition)
guard_presence(f) if {
  guard_cond := object.get(f, "guard_condition_ast_ids", [])
  count(guard_cond) > 0
}

allowed_context(f) if {
  guard_presence(f)
}

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

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,

    "file":   file,
    "class":  cls,
    "method": method,
    "line":   line,

    "fact_type": object.get(f, "fact_type", ""),
    "sink":      object.get(f, "sink", ""),
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