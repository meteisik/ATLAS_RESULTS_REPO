package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_key := "cwe284_facts"

driver_facts := [f | f := data.drivers.cwe284_facts.facts[_] ]

core_positive_condition(f) if {
  t := object.get(f, "fact_type", "")
  t == "sensitive_operation_fact"
  oks := object.get(f, "origin_kinds", [])
  is_array(oks)
  count(oks) > 0
  ovs := object.get(f, "origin_values", [])
  is_array(ovs)
  count(ovs) > 0
  sm := object.get(f, "sink_member", "")
  sm != ""
  snt := object.get(f, "sink_node_type", "")
  snt != ""
  srt := object.get(f, "sink_resolved_type", "")
  srt != ""
}

is_violation(f) if {
  core_positive_condition(f)
}

allowed_context(f) if {
  false
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
  sink := object.get(f, "sink_member", "")

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