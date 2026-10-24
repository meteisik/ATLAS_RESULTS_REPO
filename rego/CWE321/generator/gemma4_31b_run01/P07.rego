package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects cryptographic keys that are hard-coded in the source code, where the key material is proven to be compile-time fixed."

# The policy consumes facts from the designated driver for CWE321.
driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Core violation logic: a key is violating if it is proven to be compile-time fixed.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# The core positive condition identifies candidates that have provided provenance data.
# Per the committed plan, it requires origin_kinds and origin_values to be non-sentinel.
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  
  # A violation requires the key material to be exclusively literal/constant.
  every kind in kinds {
    kind == "literal"
  }

  values := object.get(f, "origin_values", [])
  count(values) > 0
}

# The runtime_source_guard (allowed_context) suppresses findings where key material 
# is derived from runtime sources (e.g., parameters, fields, generated values).
# If any origin is not a 'literal', the key is not compile-time fixed.
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

# findings: normalize violating facts into a standard structure.
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  # Extract location and identity from the fact.
  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation: Hard-coded cryptographic key detected at %s.%s (line %v)", [
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

# deny: human-readable messages for each finding.
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}