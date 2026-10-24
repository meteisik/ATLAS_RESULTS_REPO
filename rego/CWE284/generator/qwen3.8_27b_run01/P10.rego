package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects sensitive data-modifying operations (PreparedStatement.executeUpdate) that execute without a valid authorization check on the bound value."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

core_positive_condition(f) if {
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  oa := object.get(f, "origin_ast_ids", [])
  is_array(oa)
  count(oa) > 0
  ok := object.get(f, "origin_kinds", [])
  is_array(ok)
  count(ok) > 0
  ov := object.get(f, "origin_values", [])
  is_array(ov)
  count(ov) > 0
  gc := object.get(f, "guard_condition_ast_ids", [])
  is_array(gc)
  count(gc) == 0
  gs := object.get(f, "guard_subject_origin_ast_ids", [])
  is_array(gs)
  count(gs) == 0
}

subject_matches(f) if {
  subjects := object.get(f, "guard_subject_origin_ast_ids", [])
  is_array(subjects)
  count(subjects) > 0
  origins := object.get(f, "origin_ast_ids", [])
  is_array(origins)
  count(origins) > 0
  some s in subjects
  some o in origins
  s == o
}

guard_polarity_ok(f) if {
  branches := object.get(f, "guard_sink_branches", [])
  operators := object.get(f, "guard_condition_operators", [])
  count(branches) > 0
  some i
  branches[i] == "thenPart"
  operators[i] != "!"
}

guard_polarity_ok(f) if {
  branches := object.get(f, "guard_sink_branches", [])
  operators := object.get(f, "guard_condition_operators", [])
  count(branches) > 0
  some i
  branches[i] == "elsePart"
  operators[i] == "!"
}

guard_polarity_ok(f) if {
  branches := object.get(f, "guard_sink_branches", [])
  exits := object.get(f, "guard_exit_edges", [])
  operators := object.get(f, "guard_condition_operators", [])
  count(branches) > 0
  some i
  branches[i] == ""
  exits[i] == "elsePart"
  operators[i] != "!"
}

guard_polarity_ok(f) if {
  branches := object.get(f, "guard_sink_branches", [])
  exits := object.get(f, "guard_exit_edges", [])
  operators := object.get(f, "guard_condition_operators", [])
  count(branches) > 0
  some i
  branches[i] == ""
  exits[i] == "thenPart"
  operators[i] == "!"
}

has_valid_guard(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  is_array(guards)
  count(guards) > 0
  subject_matches(f)
  guard_polarity_ok(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not has_valid_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)
  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)
  desc := sprintf("Missing access control: %s.%s executes without valid authorization at line %v", [cls, method, line])
  finding := {
    "policy_id": policy_id,
    "title": title,
    "severity": severity,
    "description": desc,
    "file": file,
    "class": cls,
    "method": method,
    "line": line,
    "fact_type": "sensitive_operation_fact",
    "sink": object.get(f, "sink_member", ""),
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}