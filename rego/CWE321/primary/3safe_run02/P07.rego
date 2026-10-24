package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material in SecretKeySpec constructions."

# Driver facts source
driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Core condition: all origins are literals and at least one literal value exists
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  every k in origin_kinds { k == "literal" }

  origin_vals := object.get(f, "origin_values", [])
  count(origin_vals) >= 1
  every v in origin_vals { v != "" }
}

# A fact is a violation if it satisfies the core condition
is_violation(f) if {
  core_positive_condition(f)
}

# Findings: normalize violating facts
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
    policy_id,
    cls,
    method,
    line,
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

# Human‑readable deny messages
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