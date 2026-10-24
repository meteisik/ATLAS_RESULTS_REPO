package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects cryptographic keys that are hard-coded in the source code, where the key material is proven to be compile-time fixed."

# The plugin emits facts with this specific type.
primary_fact_type := "crypto_key_material_fact"

# Driver key this policy consumes facts from.
driver_key := "cwe321_facts"

# Canonical fact list for this policy.
driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Core violation logic.
# A violation occurs if the key material is proven to be compile-time fixed
# (all origins are literals) and the sink is a SecretKeySpec construction.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# The core "this looks bad" condition.
# Requirements based on COMMITTED_POLICY_PLAN and measured discriminators:
# 1. Sink must be a SecretKeySpec class creator.
# 2. Key material provenance must be non-sentinel.
# 3. All provenance origins must be 'literal'.
core_positive_condition(f) if {
  # Required identity and structure checks
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.SecretKeySpec"
  object.get(f, "sink_member", "") == "SecretKeySpec"
  object.get(f, "sink_node_type", "") == "class_creator"

  # Evidence of hard-coded material
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds {
    kind == "literal"
  }

  # Ensure values are also provided (non-sentinel)
  values := object.get(f, "origin_values", [])
  count(values) > 0
}

# Guard against runtime-derived material.
# A key is safe if it is provisioned at runtime, which is evidenced by 
# the presence of any origin kind other than 'literal'.
# This suppresses findings where keys are assembled from both literals and runtime data.
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

# findings: normalize violating facts into a standard structure.
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  # Robust field extraction from facts schema
  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation: Hard-coded cryptographic key detected in %s.%s (line %v)", [
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