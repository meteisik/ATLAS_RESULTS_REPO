package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

# Driver key this policy consumes facts from.
driver_key := "cwe284_facts"

# Optional: primary fact_type this policy cares about (metadata only).
primary_fact_type := "sensitive_operation_fact"

# Canonical fact list for this policy
driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core violation logic
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Hook 1: the core "this looks bad" condition.
# A fact is considered a violation candidate if:
#   * it is a sensitive_operation_fact
#   * all origin_kinds are "call_result"
#   * all origin_values are "getenv"
#   * guard_subject_origin_ast_ids is empty OR has no intersection with origin_ast_ids
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sensitive_operation_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every k in origin_kinds { k == "call_result" }

  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
  every v in origin_values { v == "getenv" }

  guard_subject_origin_ast_ids := object.get(f, "guard_subject_origin_ast_ids", [])
  origin_ast_ids := object.get(f, "origin_ast_ids", [])

  count(guard_subject_origin_ast_ids) == 0
}

core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sensitive_operation_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every k in origin_kinds { k == "call_result" }

  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
  every v in origin_values { v == "getenv" }

  guard_subject_origin_ast_ids := object.get(f, "guard_subject_origin_ast_ids", [])
  origin_ast_ids := object.get(f, "origin_ast_ids", [])

  count(guard_subject_origin_ast_ids) > 0
  every id in guard_subject_origin_ast_ids { not id in origin_ast_ids }
}

# Hook 3: safe/allowed contexts to subtract out false positives.
# A safe execution is protected by an authorization check whose subject origin intersects the statement origin.
allowed_context(f) if {
  guard_call_names := object.get(f, "guard_call_names", [])
  some name in guard_call_names
  name == "isAuthorized"

  guard_subject_origin_ast_ids := object.get(f, "guard_subject_origin_ast_ids", [])
  origin_ast_ids := object.get(f, "origin_ast_ids", [])

  some id in guard_subject_origin_ast_ids
  id in origin_ast_ids
}

# findings: normalize violating facts into a standard structure
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
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
  }
]

# deny: human-readable messages for each finding
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}