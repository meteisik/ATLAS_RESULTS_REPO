package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

core_positive_condition(f) if {
  some ok in object.get(f, "origin_kinds", [])
  true
  some ov in object.get(f, "origin_values", [])
  true
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"
  some gca in object.get(f, "guard_call_ast_ids", [])
  true
  some gsoi in object.get(f, "guard_subject_origin_ast_ids", [])
  true
  some gca2 in object.get(f, "guard_condition_ast_ids", [])
  true
}

guard_call_presence(f) if {
  some gca in object.get(f, "guard_call_ast_ids", [])
  true
}

guard_condition_exists(f) if {
  some gca in object.get(f, "guard_condition_ast_ids", [])
  true
}

guard_subject_origin_match(f) if {
  object.get(f, "guard_subject_origin_ast_ids", []) == object.get(f, "origin_ast_ids", [])
}

guard_call_name_is_authorized(f) if {
  some name in object.get(f, "guard_call_names", [])
  name == "isAuthorized"
}

is_violation(f) if {
  not core_positive_condition(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_call_presence(f)
}

is_violation(f) if {
  core_positive_condition(f)
  guard_call_presence(f)
  not guard_condition_exists(f)
}

is_violation(f) if {
  core_positive_condition(f)
  guard_call_presence(f)
  guard_condition_exists(f)
  not guard_subject_origin_match(f)
}

is_violation(f) if {
  core_positive_condition(f)
  guard_call_presence(f)
  guard_condition_exists(f)
  guard_subject_origin_match(f)
  not guard_call_name_is_authorized(f)
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
    v.policy_id,
    v.title,
    file,
    line,
  ])
}