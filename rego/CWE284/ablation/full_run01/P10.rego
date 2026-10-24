package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects JDBC executeUpdate operations that are performed without proper authorization checks."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "sensitive_operation_fact"

  klist := object.get(f, "origin_kinds", [])
  vlist := object.get(f, "origin_values", [])
  count(klist) > 0
  count(vlist) > 0

  some i
  i < count(klist)
  kind := klist[i]
  kind != ""
  val := vlist[i]
  val != ""
}

allowed_context(f) if {
  guard_calls := object.get(f, "guard_call_ast_ids", [])
  guard_subject_vals := object.get(f, "guard_subject_origin_values", [])
  count(guard_calls) > 0
  some gv in guard_subject_vals
  some ov in object.get(f, "origin_values", [])
  gv == ov
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

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