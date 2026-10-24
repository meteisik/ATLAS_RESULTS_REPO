package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects data-modifying statements that execute without a matching authorization guard."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core positive condition: fact must be of the correct type and have
# non‑sentinel origin information.
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sensitive_operation_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])

  # Require at least one aligned, non‑empty origin entry.
  some i
  origin_kinds[i] != ""
  origin_values[i] != ""
}

# Guard rule 1: any guard‑related metadata present ⇒ potentially safe.
guard_presence_rule(f) if {
  some _ in object.get(f, "guard_condition_ast_ids", [])
}
guard_presence_rule(f) if {
  some _ in object.get(f, "guard_condition_operators", [])
}
guard_presence_rule(f) if {
  some _ in object.get(f, "guard_exit_edges", [])
}
guard_presence_rule(f) if {
  some _ in object.get(f, "guard_sink_branches", [])
}
guard_presence_rule(f) if {
  some _ in object.get(f, "guard_subject_origin_ast_ids", [])
}
guard_presence_rule(f) if {
  some _ in object.get(f, "guard_subject_origin_kinds", [])
}
guard_presence_rule(f) if {
  some _ in object.get(f, "guard_subject_origin_values", [])
}

# Guard rule 2: guard subject origins intersect operation origins.
guard_subject_origin_match_rule(f) if {
  origin_ast_ids := object.get(f, "origin_ast_ids", [])
  origin_kinds   := object.get(f, "origin_kinds", [])
  origin_values  := object.get(f, "origin_values", [])

  guard_ast_ids  := object.get(f, "guard_subject_origin_ast_ids", [])
  guard_kinds    := object.get(f, "guard_subject_origin_kinds", [])
  guard_values   := object.get(f, "guard_subject_origin_values", [])

  some i
  some j
  origin_ast_ids[i] == guard_ast_ids[j]
  origin_kinds[i]   == guard_kinds[j]
  origin_values[i]  == guard_values[j]
}

# Guard rule 3: presence of a condition operator (e.g., '!') indicates a guard.
guard_operator_evaluation_rule(f) if {
  some _ in object.get(f, "guard_condition_operators", [])
}

# An execution is considered safe if any guard rule matches.
allowed_context(f) if {
  guard_presence_rule(f)
}
allowed_context(f) if {
  guard_subject_origin_match_rule(f)
}
allowed_context(f) if {
  guard_operator_evaluation_rule(f)
}

# Violation predicate.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: normalized structure for downstream consumption.
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
    "sink":        object.get(f, "sink", ""),
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