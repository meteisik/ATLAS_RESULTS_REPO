package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file path constructions that include runtime-derived input, potentially enabling path traversal attacks."

driver_facts := [f | f := data.drivers.cwe22_facts.facts[_]]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  some kind in kinds
  kind == "call_result"
  values := object.get(f, "origin_values", [])
  count(values) > 0
}

allowed_context(f) if { false }

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := ""
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink_member", "")

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

    "sink_ast_id": object.get(f, "sink_ast_id", 0),
    "sink_member": object.get(f, "sink_member", ""),
    "sink_node_type": object.get(f, "sink_node_type", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
    "origin_kinds": object.get(f, "origin_kinds", []),
    "origin_values": object.get(f, "origin_values", []),
    "origin_ast_ids": object.get(f, "origin_ast_ids", [])
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