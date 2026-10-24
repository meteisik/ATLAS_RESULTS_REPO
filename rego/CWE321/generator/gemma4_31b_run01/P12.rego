package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects cryptographic keys that are hard-coded in the source code, where the key material is proven to be compile-time fixed."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  # Requirement: sink_resolved_type must be 'javax.crypto.spec.SecretKeySpec'
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.SecretKeySpec"

  # Requirement: origin_kinds must be non-sentinel AND all elements must be members of {'literal', 'constant'}
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds {
    is_fixed_kind(k)
  }

  # Requirement: origin_values must be non-sentinel
  values := object.get(f, "origin_values", [])
  count(values) > 0
}

is_fixed_kind(k) if {
  k == "literal"
}

is_fixed_kind(k) if {
  k == "constant"
}

allowed_context(f) if {
  # Runtime provenance guard: Ensure key material is not derived from runtime sources.
  # If any element in origin_kinds is NOT a fixed kind, it is runtime-derived.
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  not is_fixed_kind(k)
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

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}