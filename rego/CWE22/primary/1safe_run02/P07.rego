package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file path constructions that include runtime‑derived input, potentially enabling path traversal attacks."

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Helper: true if v looks like a literal path (starts with "/")
is_literal_value(v) if { startswith(v, "/") }

# Helper: true if origin_kinds contains "call_result"
kind_contains_call_result(f) if {
  ks := object.get(f, "origin_kinds", [])
  some k in ks
  k == "call_result"
}

# Helper: true if origin_values contains a non‑literal runtime value
runtime_value_present(f) if {
  vs := object.get(f, "origin_values", [])
  some v in vs
  not is_literal_value(v)
}

# Core positive condition: either a call_result origin or a runtime value
core_positive_condition(f) if { kind_contains_call_result(f) }
core_positive_condition(f) if { runtime_value_present(f) }

# Guard: all origins are literals
safe_literal_path_guard(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  every k in ks { k == "literal" }
  every v in vs { startswith(v, "/") }
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_literal_path_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := severity
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
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
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
    "sink_member": object.get(f, "sink_member", ""),
    "sink_node_type": object.get(f, "sink_node_type", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
    "origin_kinds": object.get(f, "origin_kinds", []),
    "origin_values": object.get(f, "origin_values", [])
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line
  ])
}