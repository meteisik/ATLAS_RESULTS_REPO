package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f | f := data.drivers.cwe284_facts.facts[_]]

all_in(a, b) if {
  count(a) == count(b)
  every v in a {
    some w in b
    v == w
  }
}

guard_matches_origin(f) if {
  guard_ids := f.guard_subject_origin_ast_ids
  origin_ids := f.origin_ast_ids
  all_in(guard_ids, origin_ids)
  all_in(origin_ids, guard_ids)
  guard_vals := f.guard_subject_origin_values
  origin_vals := f.origin_values
  all_in(guard_vals, origin_vals)
  all_in(origin_vals, guard_vals)
}

empty_guard(f) if {
  count(f.guard_call_ast_ids) == 0
}

allowed_context(f) if {
  guard_names := f.guard_call_names
  some name in guard_names
  name == "isAuthorized"
  guard_cond_ids := f.guard_condition_ast_ids
  count(guard_cond_ids) > 0
  guard_matches_origin(f)
}

core_positive_condition(f) if {
  kinds := f.origin_kinds
  count(kinds) == 1
  kinds[0] == "call_result"
  vals := f.origin_values
  count(vals) == 1
  vals[0] == "getenv"
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
  sev := severity
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")
  desc := sprintf("Policy %s violation at %s.%s (line %v)", [policy_id, cls, method, line])
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
    "sink":        sink
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}