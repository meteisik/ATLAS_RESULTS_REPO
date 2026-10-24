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
  
  # Ensure bound parameters exist (non-sentinel)
  count(f.origin_kinds) > 0
  count(f.origin_values) > 0
}

allowed_context(f) if {
  # A fact is safe if there is at least one guard that is both logically effective 
  # and the authorization decision is about the value bound to the sink.
  some i
  f.guard_condition_ast_ids[i]
  
  is_guard_effective(f, i)
  is_subject_correct(f)
}

is_guard_effective(f, i) if {
  # Case 1: Sink is in the thenPart and condition is not negated
  # Path: Condition(True) -> thenPart -> Sink
  f.guard_sink_branches[i] == "thenPart"
  f.guard_condition_operators[i] == ""
}

is_guard_effective(f, i) if {
  # Case 2: Sink is in the elsePart and condition is negated
  # Path: Condition(False) -> !Condition(True) -> elsePart -> Sink
  f.guard_sink_branches[i] == "elsePart"
  f.guard_condition_operators[i] == "!"
}

is_guard_effective(f, i) if {
  # Case 3: Preceding guard that exits on the false branch (elsePart) and is not negated
  # Path: Condition(True) -> Continue to Sink; Condition(False) -> elsePart -> Exit
  f.guard_sink_branches[i] == ""
  f.guard_exit_edges[i] == "elsePart"
  f.guard_condition_operators[i] == ""
}

is_subject_correct(f) if {
  # Check for intersection between the subject of the authorization check 
  # and the values bound to the sensitive operation.
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