package policies.cwe22
import rego.v1

# Policy metadata
policy_id   := "CWE22"
title      := "Path traversal"
severity   := "HIGH"
description := "Detects file path constructions that include runtime-derived input, potentially enabling path traversal attacks."

# Driver key and primary fact type (for documentation; not required in logic)
driver_key       := "cwe22_facts"
primary_fact_type := "file_path_fact"

# Canonical fact list from the driver
driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Helper: check if a list contains a specific value
contains_value(list, val) := true if {
  some v in list
  v == val
}

# Core positive condition: at least one call_result origin and a runtime-derived value (e.g., getenv)
core_positive_condition(f) if {
  kinds  := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  contains_value(kinds, "call_result")
  contains_value(values, "getenv")
}

# Optional guard rule (does not override core condition)
safe_literal_origin(f) if {
  kinds  := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  not contains_value(kinds, "call_result")
  not contains_value(values, "getenv")
}

# A fact is a violation if it satisfies the core condition
is_violation(f) if {
  core_positive_condition(f)
}

# Findings: collect violating facts into a standard structure
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink_member", "")

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

    # Additional context for debugging
    "sink_ast_id":     object.get(f, "sink_ast_id", 0),
    "sink_member":    object.get(f, "sink_member", ""),
    "sink_node_type": object.get(f, "sink_node_type", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
    "origin_kinds":   object.get(f, "origin_kinds", []),
    "origin_values":  object.get(f, "origin_values", []),
  }
]

# Human‑readable denial messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line
  ])
}