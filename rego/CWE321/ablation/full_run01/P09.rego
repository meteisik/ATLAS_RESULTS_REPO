package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can detect hard‑coded effective keys."

# Driver facts list
driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard: all origin_kinds must be literal
guard_literal_origin(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every kind in origin_kinds { kind == "literal" }
}

# Core positive condition
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])
  count(origin_kinds) > 0
  count(origin_values) > 0
  every kind in origin_kinds { kind == "literal" }
  every val in origin_values { val != "" }
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "javax.crypto.spec.SecretKeySpec"
}

# Violation rule
is_violation(f) if {
  core_positive_condition(f)
  guard_literal_origin(f)
}

# Findings
findings := [v |
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

# Human-readable messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}