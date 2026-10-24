package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects sensitive data-modifying operations that execute without a matching authorization check on the bound values."

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
  count(f.origin_ast_ids) > 0
}

allowed_context(f) if {
  some i
  f.guard_condition_ast_ids[i]
  is_guard_effective(f, i)
  is_subject_correct(f)
}

is_guard_effective(f, i) if {
  f.guard_sink_branches[i] == "thenPart"
  f.guard_condition_operators[i] != "!"
}

is_guard_effective(f, i) if {
  f.guard_sink_branches[i] == ""
  f.guard_exit_edges[i] == "elsePart"
  f.guard_condition_operators[i] != "!"
}

is_guard_effective(f, i) if {
  f.guard_sink_branches[i] == "elsePart"
  f.guard_condition_operators[i] == "!"
}

is_guard_effective(f, i) if {
  f.guard_sink_branches[i] == ""
  f.guard_exit_edges[i] == "thenPart"
  f.guard_condition_operators[i] == "!"
}

is_subject_correct(f) if {
  some sub in f.guard_subject_origin_ast_ids
  some ori in f.origin_ast_ids
  sub == ori
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

  desc := sprintf("Policy %s violation at %s.%s (line %v): sensitive operation executes without valid authorization check on bound values", [
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