package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects construction of java.io.File paths that include runtime-provided input appended to a constant root."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  object.get(f, "sink_member", "") == "File"
  object.get(f, "sink_node_type", "") == "class_creator"
  object.get(f, "sink_resolved_type", "") == "java.io.File"

  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(vals) > 0
  count(kinds) == count(vals)

  some i; kind := kinds[i]
  kind == "call_result"
  val := vals[i]
  not regex.match("^/", val)
}

allowed_context(f) if {
  safe_literal_path_guard(f)
}

safe_literal_path_guard(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(vals) > 0
  count(kinds) == count(vals)
  every kind in kinds { kind == "literal" }
  every val in vals { regex.match("^/", val) }
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