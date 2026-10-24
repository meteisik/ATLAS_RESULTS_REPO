package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Sensitive data-modifying operations (PreparedStatement.executeUpdate) that execute without a matching authorization check on the bound value."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core positive condition: the fact must represent a valid sensitive operation
# with traceable bound-value origins (all unanimous violating discriminators).
core_positive_condition(f) if {
  object.get(f, "sink_ast_id", 0) != 0
  object.get(f, "sink_member", "") != ""
  object.get(f, "sink_resolved_type", "") != ""
  object.get(f, "sink_node_type", "") == "method_invocation"
  origins := object.get(f, "origin_ast_ids", [])
  is_array(origins)
  count(origins) > 0
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
}

# Guard rule 1: unguarded execution — no if-statement decides whether sink runs.
unguarded_execution(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) == 0
}

# Guard rule 2: subject mismatch — guard exists but its subject origins
# do not intersect the bound-value origins (decision is about a different value).
subject_mismatch(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  subjects := object.get(f, "guard_subject_origin_ast_ids", [])
  origins := object.get(f, "origin_ast_ids", [])
  not subjects_intersect_origins(subjects, origins)
}

subjects_intersect_origins(subjects, origins) if {
  some s in subjects
  some o in origins
  s == o
}

# Guard rule 3: branch logic inversion — the guard branch does not permit
# execution only when the authorization decision holds.
#
# SAFE combinations (sink runs only when underlying authz is true):
#   thenPart, no '!'          → condition true  → authz true
#   elsePart, '!'             → condition false, negated → authz true
#   preceding exits elsePart, no '!' → condition true → authz true
#   preceding exits thenPart, '!'    → condition false, negated → authz true
#
# UNSAFE combinations (violation):
#   thenPart, '!'             → condition true, negated → authz false
#   elsePart, no '!'          → condition false → authz false
#   preceding exits elsePart, '!' → condition true, negated → authz false
#   preceding exits thenPart, no '!' → condition false → authz false

branch_inverts_authorization(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  branches := object.get(f, "guard_sink_branches", [])
  ops := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guards)
  branches[i] == "thenPart"
  ops[i] == "!"
}

branch_inverts_authorization(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  branches := object.get(f, "guard_sink_branches", [])
  ops := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guards)
  branches[i] == "elsePart"
  ops[i] != "!"
}

branch_inverts_authorization(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  branches := object.get(f, "guard_sink_branches", [])
  exits := object.get(f, "guard_exit_edges", [])
  ops := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guards)
  branches[i] == ""
  exits[i] == "elsePart"
  ops[i] == "!"
}

branch_inverts_authorization(f) if {
  guards := object.get(f, "guard_condition_ast_ids", [])
  count(guards) > 0
  branches := object.get(f, "guard_sink_branches", [])
  exits := object.get(f, "guard_exit_edges", [])
  ops := object.get(f, "guard_condition_operators", [])
  some i
  i < count(guards)
  branches[i] == ""
  exits[i] == "thenPart"
  ops[i] != "!"
}

# A fact is a violation if it meets the core condition AND fails at least one guard rule.
is_violation(f) if {
  core_positive_condition(f)
  unguarded_execution(f)
}

is_violation(f) if {
  core_positive_condition(f)
  subject_mismatch(f)
}

is_violation(f) if {
  core_positive_condition(f)
  branch_inverts_authorization(f)
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