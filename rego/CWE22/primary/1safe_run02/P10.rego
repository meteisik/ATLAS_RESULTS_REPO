package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file path constructions that include runtime-derived input, potentially enabling path traversal attacks."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

#
# Helper: true if any kind is not "literal"
#
contains_non_literal(kinds) if {
  some k in kinds
  k != "literal"
}

#
# Helper: true if any value is likely a runtime value (does not contain a slash)
#
any_runtime_value(values) if {
  some v in values
  not regex.match(".*[/].*", v)
}

#
# Core positive condition: path includes a non‑literal origin kind and a runtime value
#
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  contains_non_literal(kinds)
  any_runtime_value(values)
}

#
# Safe guard: all origins are literal and all values are literal strings
#
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  not contains_non_literal(kinds)
  not any_runtime_value(values)
}

#
# Violation rule
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings: structured output for each violating fact
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
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
    "origin_kinds": object.get(f, "origin_kinds", []),
    "origin_values": object.get(f, "origin_values", []),
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
    "sink_member": object.get(f, "sink_member", ""),
    "sink_node_type": object.get(f, "sink_node_type", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
  }
]

#
# Human‑readable denial messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}