package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects data-modifying statements that execute without a matching authorization guard."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core positive condition: identify the sensitive operation facts we care about.
core_positive_condition(f) if {
  object.get(f, "origin_kinds", []) == ["call_result"]
  object.get(f, "origin_values", []) == ["getenv"]
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
}

# Guard rule: any guard information present.
guard_nonempty(f) if {
  some _ in object.get(f, "guard_call_ast_ids", [])
}
guard_nonempty(f) if {
  some _ in object.get(f, "guard_condition_ast_ids", [])
}

# Guard rule: guard decision must concern the same origin as the operation.
guard_subject_matches_origin(f) if {
  some g_ast in object.get(f, "guard_subject_origin_ast_ids", [])
  some o_ast in object.get(f, "origin_ast_ids", [])
  g_ast == o_ast
  some g_kind in object.get(f, "guard_subject_origin_kinds", [])
  some o_kind in object.get(f, "origin_kinds", [])
  g_kind == o_kind
  some g_val in object.get(f, "guard_subject_origin_values", [])
  some o_val in object.get(f, "origin_values", [])
  g_val == o_val
}

# Allowed (safe) context: guard present and matches origin.
allowed_context(f) if {
  guard_nonempty(f)
  guard_subject_matches_origin(f)
}

# Violation predicate.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings.
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