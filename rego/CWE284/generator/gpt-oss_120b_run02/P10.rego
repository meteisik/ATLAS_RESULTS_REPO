package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

# Driver facts source
driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core positive condition: identifies the facts that represent potentially violating executions
core_positive_condition(f) if {
  object.get(f, "origin_kinds", []) == ["call_result"]
  object.get(f, "origin_values", []) == ["getenv"]
  count(object.get(f, "guard_condition_ast_ids", [])) == 0
  count(object.get(f, "guard_call_ast_ids", [])) == 0
  count(object.get(f, "guard_subject_origin_ast_ids", [])) == 0
  count(object.get(f, "guard_subject_origin_kinds", [])) == 0
  count(object.get(f, "guard_subject_origin_values", [])) == 0
}

# Guard rule 1: presence of any guard information
guard_presence_rule(f) if {
  count(object.get(f, "guard_condition_ast_ids", [])) > 0
}
guard_presence_rule(f) if {
  count(object.get(f, "guard_call_ast_ids", [])) > 0
}

# Guard rule 2: guard decision aligns with the origin of the sink
guard_subject_alignment_rule(f) if {
  count(object.get(f, "guard_subject_origin_ast_ids", [])) == 0
}
guard_subject_alignment_rule(f) if {
  # aligned iteration over the guard‑subject and origin lists
  some i
  i < count(object.get(f, "guard_subject_origin_ast_ids", []))
  g_ast := object.get(f, "guard_subject_origin_ast_ids", [])[i]
  o_ast := object.get(f, "origin_ast_ids", [])[i]
  g_ast == o_ast

  g_kind := object.get(f, "guard_subject_origin_kinds", [])[i]
  o_kind := object.get(f, "origin_kinds", [])[i]
  g_kind == o_kind

  g_val := object.get(f, "guard_subject_origin_values", [])[i]
  o_val := object.get(f, "origin_values", [])[i]
  g_val == o_val
}

# Guard rule 3: consistency of guard branches and operators
guard_branch_consistency_rule(f) if {
  count(object.get(f, "guard_condition_ast_ids", [])) == 0
}
guard_branch_consistency_rule(f) if {
  gc := object.get(f, "guard_condition_ast_ids", [])
  gs := object.get(f, "guard_sink_branches", [])
  ge := object.get(f, "guard_exit_edges", [])
  go := object.get(f, "guard_condition_operators", [])
  count(gc) == count(gs)
  count(gc) == count(ge)
  count(gc) == count(go)
}

# Allowed (safe) context: all guard rules succeed
allowed_context(f) if {
  guard_presence_rule(f)
  guard_subject_alignment_rule(f)
  guard_branch_consistency_rule(f)
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: normalized structure for each violating fact
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
    "sink":      object.get(f, "sink", ""),
  }
]

# Human‑readable deny messages
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