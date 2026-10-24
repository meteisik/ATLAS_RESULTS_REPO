package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can detect hard‑coded effective keys."

driver_key := "cwe321_facts"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

#
# Core violation logic
#
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every kind in origin_kinds { kind == "literal" }

  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
}

runtime_origin_guard(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some kind in origin_kinds
  kind != "literal"
}

allowed_context(f) if {
  runtime_origin_guard(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
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
  }
]

#
# Deny messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}