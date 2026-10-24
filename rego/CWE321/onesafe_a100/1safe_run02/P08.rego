package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Helper to compare a list to a literal list of one element
exactly_one_literal(f, kind) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) == 1
  kinds[0] == kind
}

# Core violation condition: all required evidence present and indicates a literal key
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == primary_fact_type

  exactly_one_literal(f, "literal")

  values := object.get(f, "origin_values", [])
  count(values) > 0

  object.get(f, "sink_member", "") == "SecretKeySpec"
  object.get(f, "sink_node_type", "") == "class_creator"
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.SecretKeySpec"
}

# Guard to exclude safe contexts: any origin that is not purely literal
safe_key_guard(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) != 1
  not exactly_one_literal(f, "literal")
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_key_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
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