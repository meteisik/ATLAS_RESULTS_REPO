package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects sensitive JDBC executeUpdate calls that are either unguarded or guarded by a check that does not validate the specific value being operated upon."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  f.sink_member == "executeUpdate"
  f.sink_node_type == "method_invocation"
  f.sink_resolved_type == "java.sql.PreparedStatement"
  
  count(f.origin_kinds) > 0
  count(f.origin_values) > 0
}

allowed_context(f) if {
  count(f.guard_condition_ast_ids) > 0
  not path_is_false(f)
  authz_subject_matches_origin(f)
}

path_is_false(f) if {
  some i
  i < count(f.guard_sink_branches)
  branch := f.guard_sink_branches[i]
  op := f.guard_condition_operators[i]
  is_false_outcome(branch, op)
}

is_false_outcome(branch, op) if {
  branch == "thenPart"
  op == "!"
}

is_false_outcome(branch, op) if {
  branch == "elsePart"
  op == ""
}

authz_subject_matches_origin(f) if {
  some subject_id in f.guard_subject_origin_ast_ids
  some origin_id in f.origin_ast_ids
  subject_id == origin_id
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v): sensitive operation executeUpdate is missing a valid authorization check on the bound value.", [
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