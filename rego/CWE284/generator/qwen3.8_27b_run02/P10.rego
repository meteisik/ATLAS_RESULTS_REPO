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
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
  origins := object.get(f, "origin_ast_ids", [])
  is_array(origins)
  count(origins) > 0
}

subject_overlaps_origin(f) if {
  subjects := object.get(f, "guard_subject_origin_ast_ids", [])
  origins := object.get(f, "origin_ast_ids", [])
  is_array(subjects)
  is_array(origins)
  count(subjects) > 0
  count(origins) > 0
  some s in subjects
  some o in origins
  s == o
}

guard_suppresses(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  branches := object.get(f, "guard_sink_branches", [])
  exits := object.get(f, "guard_exit_edges", [])
  ops := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guards)
  branches[i] == "thenPart"
  exits[i] == ""
  ops[i] != "!"
  subject_overlaps_origin(f)
}

guard_suppresses(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  branches := object.get(f, "guard_sink_branches", [])
  exits := object.get(f, "guard_exit_edges", [])
  ops := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guards)
  branches[i] == "elsePart"
  exits[i] == ""
  ops[i] == "!"
  subject_overlaps_origin(f)
}

guard_suppresses(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  branches := object.get(f, "guard_sink_branches", [])
  exits := object.get(f, "guard_exit_edges", [])
  ops := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guards)
  branches[i] == ""
  exits[i] == "elsePart"
  ops[i] != "!"
  subject_overlaps_origin(f)
}

guard_suppresses(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  branches := object.get(f, "guard_sink_branches", [])
  exits := object.get(f, "guard_exit_edges", [])
  ops := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guards)
  branches[i] == ""
  exits[i] == "thenPart"
  ops[i] == "!"
  subject_overlaps_origin(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_suppresses(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  sink   := object.get(f, "sink_member", "")
  ftype  := object.get(f, "fact_type", "sensitive_operation_fact")

  desc := sprintf("Policy %s violation: unguarded or mismatched authorization on %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
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
  cls  := object.get(v, "class", "")
  meth := object.get(v, "method", "")

  msg := sprintf("[%s] %s at %s:%d (%s.%s)", [
    v.policy_id, v.title, file, line, cls, meth,
  ])
}