package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core positive condition matches the discriminating fields for violations
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sensitive_operation_fact"

  ok_kinds := object.get(f, "origin_kinds", [])
  count(ok_kinds) == 1
  ok_kinds[0] == "call_result"

  ok_vals := object.get(f, "origin_values", [])
  count(ok_vals) == 1
  ok_vals[0] == "getenv"

  guard_conds := object.get(f, "guard_condition_ast_ids", [])
  count(guard_conds) == 0

  guard_calls := object.get(f, "guard_call_ast_ids", [])
  count(guard_calls) == 0

  guard_subj := object.get(f, "guard_subject_origin_ast_ids", [])
  count(guard_subj) == 0
}

# Guard rule: sink is protected by an enclosing if‑statement
guarded_sink(f) if {
  guard_conds := object.get(f, "guard_condition_ast_ids", [])
  count(guard_conds) > 0
}

# Guard rule: guard decision is tied to the statement's bound value
guard_with_subject_origin(f) if {
  guard_calls := object.get(f, "guard_call_ast_ids", [])
  count(guard_calls) > 0

  guard_subj := object.get(f, "guard_subject_origin_ast_ids", [])
  count(guard_subj) > 0
}

# Allowed (safe) context if any guard rule matches
allowed_context(f) if {
  guarded_sink(f)
}
allowed_context(f) if {
  guard_with_subject_origin(f)
}

# Violation if core condition holds and no allowed context applies
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