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
  # Required identity and structure checks from Committed Policy Plan
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.SecretKeySpec"
  object.get(f, "sink_member", "") == "SecretKeySpec"
  object.get(f, "sink_node_type", "") == "class_creator"

  # Evidence of hard-coded material: origin_kinds and origin_values must be non-sentinel
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  
  # A violation is an effective key whose material is proven compile-time fixed:
  # origin_kinds contains only literal terminals.
  every kind in kinds {
    kind == "literal"
  }

  values := object.get(f, "origin_values", [])
  count(values) > 0
}

# Guard against runtime-derived material.
# SAFE is key material provisioned at runtime: origin_kinds contains a 
# formal parameter, configuration/registry call result, field, or generated value.
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
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