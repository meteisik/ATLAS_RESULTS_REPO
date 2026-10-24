package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Sensitive data-modifying operations (PreparedStatement.executeUpdate) that execute without a matching authorization check on the bound value."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

core_positive_condition(f) if {
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
  object.get(f, "sink_node_type", "") == "method_invocation"
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
}

unguarded_execution(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) == 0
  branches := object.get(f, "guard_sink_branches", [])
  count(branches) == 0
  exits := object.get(f, "guard_exit_edges", [])
  count(exits) == 0
  subjects := object.get(f, "guard_subject_origin_ast_ids", [])
  count(subjects) == 0
}

is_violation(f) if {
  core_positive_condition(f)
  unguarded_execution(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  sink   := object.get(f, "sink_member", "")
  ftype  := object.get(f, "fact_type", "sensitive_operation_fact")
  desc := sprintf("Sensitive data-modifying operation %s.%s (line %v) executes without authorization check on bound value", [cls, method, line])
  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
  }
]

deny contains msg if {
  v := findings[_]
  cls  := object.get(v, "class", "")
  meth := object.get(v, "method", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s.%s (line %v)", [v.policy_id, v.title, cls, meth, line])
}