package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Detect missing access control on data-modifying statements."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core positive condition: matches the vulnerable pattern
core_positive_condition(f) if {
  object.get(f, "sink_member", "") == "executeUpdate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.PreparedStatement"

  kinds := object.get(f, "origin_kinds", [])
  count(kinds) == 1
  kinds[0] == "call_result"

  vals := object.get(f, "origin_values", [])
  count(vals) == 1
  vals[0] == "getenv"
}

# Guard rule: safe when the guard's branch that contains the sink is the then‑part
guard_branch_is_then(f) if {
  branches := object.get(f, "guard_sink_branches", [])
  count(branches) > 0
  branch := branches[0]
  branch == "thenPart"
}

# Allowed (safe) context: guard permits the sink
allowed_context(f) if {
  guard_branch_is_then(f)
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
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