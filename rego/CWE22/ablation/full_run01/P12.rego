package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects construction of java.io.File paths that include runtime-provided input appended to a constant root."

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

core_positive_condition(f) if {
  sink_member := object.get(f, "sink_member", "")
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_member == "File"
  sink_node_type == "class_creator"
  sink_resolved_type == "java.io.File"

  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  count(kinds) == count(vals)

  some i
  kind := kinds[i]
  kind == "call_result"
  val := vals[i]
  val == "/home/user/uploads/"
}

core_positive_condition(f) if {
  sink_member := object.get(f, "sink_member", "")
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_member == "File"
  sink_node_type == "class_creator"
  sink_resolved_type == "java.io.File"

  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  count(kinds) == count(vals)

  some i
  kind := kinds[i]
  kind == "call_result"
  val := vals[i]
  val == "getenv"
}

guard_no_call_result(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds { kind == "literal" }
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_no_call_result(f)
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