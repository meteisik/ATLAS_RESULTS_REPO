package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Helper to extract boolean fields
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

# Extract the fact_type (or kind) if present.
fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

# Core violation logic
core_positive_condition(f) if {
  guard_cond := object.get(f, "guard_condition_ast_ids", [])
  count(guard_cond) > 0
  guard_sink := object.get(f, "guard_sink_branches", [])
  some g in guard_sink
  g == "elsePart"
  ks := object.get(f, "origin_kinds", [])
  count(ks) == 0
  vs := object.get(f, "origin_values", [])
  count(vs) == 0
  sm := object.get(f, "sink_member", "")
  sm == "executeUpdate"
  sn := object.get(f, "sink_node_type", "")
  sn == "method_invocation"
  sr := object.get(f, "sink_resolved_type", "")
  sr == "java.sql.PreparedStatement"
}

# Allowed context (safe) conditions
allowed_context(f) if {
  guard_cond := object.get(f, "guard_condition_ast_ids", [])
  guard_cond == []
}
allowed_context(f) if {
  guard_cond := object.get(f, "guard_condition_ast_ids", [])
  guard_cond != []
  guard_sink := object.get(f, "guard_sink_branches", [])
  some g in guard_sink
  g != "elsePart"
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

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
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
  method := object.get(v, "method", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}