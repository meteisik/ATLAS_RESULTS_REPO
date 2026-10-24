package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detects data-modifying JDBC executions that run without a valid authorization decision."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Guard present detection: any guard_* field non-empty
guard_present(f) if {
  count(object.get(f, "guard_call_ast_ids", [])) > 0
}
guard_present(f) if {
  count(object.get(f, "guard_call_names", [])) > 0
}
guard_present(f) if {
  count(object.get(f, "guard_condition_ast_ids", [])) > 0
}
guard_present(f) if {
  count(object.get(f, "guard_condition_operators", [])) > 0
}
guard_present(f) if {
  count(object.get(f, "guard_exit_edges", [])) > 0
}
guard_present(f) if {
  count(object.get(f, "guard_sink_branches", [])) > 0
}
guard_present(f) if {
  count(object.get(f, "guard_subject_origin_ast_ids", [])) > 0
}
guard_present(f) if {
  count(object.get(f, "guard_subject_origin_kinds", [])) > 0
}
guard_present(f) if {
  count(object.get(f, "guard_subject_origin_values", [])) > 0
}

allowed_context(f) if {
  guard_present(f)
}

# Core positive condition: all five discriminator fields must match
core_positive_condition(f) if {
  oks := object.get(f, "origin_kinds", [])
  count(oks) == 1
  oks[0] == "call_result"

  ovs := object.get(f, "origin_values", [])
  count(ovs) == 1
  ovs[0] == "getenv"

  sm := object.get(f, "sink_member", "")
  sm == "executeUpdate"

  sn := object.get(f, "sink_node_type", "")
  sn == "method_invocation"

  sr := object.get(f, "sink_resolved_type", "")
  sr == "java.sql.PreparedStatement"
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
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

# Deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line
  ])
}