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

core_positive_condition(f) if {
  object.get(f, "fact_type", "") == primary_fact_type
  ok_kinds := object.get(f, "origin_kinds", [])
  count(ok_kinds) > 0
  ok_vals := object.get(f, "origin_values", [])
  count(ok_vals) > 0
}

allowed_context(f) if {
  gcids := object.get(f, "guard_condition_ast_ids", [])
  count(gcids) > 0
}
allowed_context(f) if {
  gcalls := object.get(f, "guard_call_ast_ids", [])
  count(gcalls) > 0
}
allowed_context(f) if {
  gnames := object.get(f, "guard_call_names", [])
  count(gnames) > 0
}
allowed_context(f) if {
  gbranches := object.get(f, "guard_sink_branches", [])
  count(gbranches) > 0
}
allowed_context(f) if {
  gexits := object.get(f, "guard_exit_edges", [])
  count(gexits) > 0
}
allowed_context(f) if {
  gos := object.get(f, "guard_subject_origin_ast_ids", [])
  count(gos) > 0
}
allowed_context(f) if {
  gops := object.get(f, "guard_condition_operators", [])
  count(gops) > 0
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink", ""),
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