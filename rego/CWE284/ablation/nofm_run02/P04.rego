package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f | f := data.drivers.cwe284_facts.facts[_]]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  count(ks) == 1
  ks[0] == "call_result"

  vs := object.get(f, "origin_values", [])
  count(vs) == 1
  vs[0] == "getenv"

  sm := object.get(f, "sink_member", "")
  sm == "executeUpdate"

  sn := object.get(f, "sink_node_type", "")
  sn == "method_invocation"

  sr := object.get(f, "sink_resolved_type", "")
  sr == "java.sql.PreparedStatement"
}

allowed_context(f) if {
  gsb := object.get(f, "guard_sink_branches", [])
  count(gsb) == 1
  gsb[0] == "thenPart"
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", "")
  sink := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
    "policy_id": policy_id,
    "title": title,
    "severity": sev,
    "description": desc,
    "file": file,
    "class": cls,
    "method": method,
    "line": line,
    "fact_type": ftype,
    "sink": sink,
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