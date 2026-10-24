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

# Helper: true if origin_values contains a permitted environment value
env_value_ok(f) if {
  ovs := object.get(f, "origin_values", [])
  count(ovs) == 1
  some v in ovs
  v == "getenv"
}
env_value_ok(f) if {
  ovs := object.get(f, "origin_values", [])
  count(ovs) == 1
  some v in ovs
  v == "getProperty"
}

# Helper: true if guard_exit_edges indicates no early exit
guard_exit_ok(f) if {
  gxe := object.get(f, "guard_exit_edges", [])
  count(gxe) == 0
}
guard_exit_ok(f) if {
  gxe := object.get(f, "guard_exit_edges", [])
  count(gxe) == 1
  gxe[0] == ""
}

# Guard rule to exclude safe cases guarded by isAuthorized on the env value
guard_isAuthorized_on_env_value(f) if {
  gnc := object.get(f, "guard_call_names", [])
  some name in gnc
  name == "isAuthorized"

  gsv := object.get(f, "guard_subject_origin_values", [])
  ovs := object.get(f, "origin_values", [])
  gsv == ovs

  gsb := object.get(f, "guard_sink_branches", [])
  count(gsb) == 1
  gsb[0] == "thenPart"

  guard_exit_ok(f)
}

# Core positive condition
core_positive_condition(f) if {
  oks := object.get(f, "origin_kinds", [])
  count(oks) == 1
  oks[0] == "call_result"
  env_value_ok(f)
}

# Final violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not guard_isAuthorized_on_env_value(f)
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
  sink_id := object.get(f, "sink_ast_id", 0)

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line
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
    "sink_ast_id": sink_id
  }
]

# Human-readable denial messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line
  ])
}