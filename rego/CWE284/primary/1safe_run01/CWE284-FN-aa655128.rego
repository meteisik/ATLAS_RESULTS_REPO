package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects data-modifying JDBC executions that run without a matching authorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Small boolean-field helper
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

# Extract the fact_type (or kind) if present.
fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

# Core positive condition
core_positive_condition(f) if {
  # origin_kinds non-empty
  origin_kinds := object.get(f, "origin_kinds", [])
  is_array(origin_kinds)
  count(origin_kinds) > 0

  # origin_values non-empty
  origin_values := object.get(f, "origin_values", [])
  is_array(origin_values)
  count(origin_values) > 0

  # guard_condition_ast_ids empty
  guard_condition_ast_ids := object.get(f, "guard_condition_ast_ids", [])
  is_array(guard_condition_ast_ids)
  count(guard_condition_ast_ids) == 0

  # guard_sink_branches empty
  guard_sink_branches := object.get(f, "guard_sink_branches", [])
  is_array(guard_sink_branches)
  count(guard_sink_branches) == 0
}

# Allowed context: none for this policy
allowed_context(f) if { false }

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink_member", "")

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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}