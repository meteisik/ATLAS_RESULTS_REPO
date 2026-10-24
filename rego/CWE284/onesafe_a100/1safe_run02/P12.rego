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

core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "sensitive_operation_fact"

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

allowed_context(f) if {
  gca := object.get(f, "guard_call_ast_ids", [])
  count(gca) > 0
}
allowed_context(f) if {
  gcn := object.get(f, "guard_call_names", [])
  count(gcn) > 0
}
allowed_context(f) if {
  gca2 := object.get(f, "guard_condition_ast_ids", [])
  count(gca2) > 0
}
allowed_context(f) if {
  gco := object.get(f, "guard_condition_operators", [])
  count(gco) > 0
}
allowed_context(f) if {
  gxe := object.get(f, "guard_exit_edges", [])
  count(gxe) > 0
}
allowed_context(f) if {
  gsb := object.get(f, "guard_sink_branches", [])
  count(gsb) > 0
}
allowed_context(f) if {
  gsoi := object.get(f, "guard_subject_origin_ast_ids", [])
  count(gsoi) > 0
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
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
    v.policy_id, v.title, file, line,
  ])
}