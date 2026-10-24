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
  
  # Ensure there are bound parameters (non-sentinel evidence)
  count(f.origin_kinds) > 0
  count(f.origin_values) > 0
}

allowed_context(f) if {
  # A sink is safe if there is at least one guard that is both effective and aligned.
  count(f.guard_condition_ast_ids) > 0
  
  # Iterate over guard indices
  some i
  f.guard_condition_ast_ids[i]
  
  is_effective_guard(f, i)
  is_aligned_guard(f)
}

# A guard is effective if the path reaching the sink is logically conditioned 
# on the authorization decision being TRUE.
is_effective_guard(f, i) if {
  # Case 1: Decision is True, Path is "True" (Sink in thenPart or precedes and exits through elsePart)
  branch := f.guard_sink_branches[i]
  exit := f.guard_exit_edges[i]
  op := f.guard_condition_operators[i]
  
  op != "!"
  is_true_path(branch, exit)
}

is_effective_guard(f, i) if {
  # Case 2: Decision is True, Path is "False" (Sink in elsePart or precedes and exits through thenPart)
  # This happens if the condition expression is negated (!), making the outcome False 
  # equivalent to a True decision.
  branch := f.guard_sink_branches[i]
  exit := f.guard_exit_edges[i]
  op := f.guard_condition_operators[i]
  
  op == "!"
  is_false_path(branch, exit)
}

is_true_path(branch, exit) if {
  branch == "thenPart"
}

is_true_path(branch, exit) if {
  branch == ""
  exit == "elsePart"
}

is_false_path(branch, exit) if {
  branch == "elsePart"
}

is_false_path(branch, exit) if {
  branch == ""
  exit == "thenPart"
}

is_aligned_guard(f) if {
  # Alignment: The authorization decision must be about the value bound into the statement.
  # One of the guard's subject origins must be one of the sensitive operation's origins.
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