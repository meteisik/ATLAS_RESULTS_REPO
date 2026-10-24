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

# Guard call presence
guard_call_present(f) if {
  count(f.guard_call_ast_ids) > 0
}

# Guard subject origin contains getenv
guard_subject_has_getenv(f) if {
  some val in f.guard_subject_origin_values
  val == "getenv"
}

# Safe context: guarded by a method call that checks getenv
allowed_context(f) if {
  guard_call_present(f)
  guard_subject_has_getenv(f)
}

# Core positive condition based on unanimous discriminators
core_positive_condition(f) if {
  f.fact_type == "sensitive_operation_fact"
  f.origin_kinds == ["call_result"]
  f.origin_values == ["getenv"]
  f.sink_member == "executeUpdate"
  f.sink_node_type == "method_invocation"
  f.sink_resolved_type == "java.sql.PreparedStatement"
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