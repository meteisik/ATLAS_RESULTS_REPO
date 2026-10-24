package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects cryptographic keys that are hard-coded in the source code, where the key material is proven to be compile-time fixed."

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# The core positive condition identifies potential hard-coded keys.
# It requires the sink to be a SecretKeySpec (either via constructor or factory)
# and the provenance to be exclusively composed of literal constants.
core_positive_condition(f) if {
  # 1. Sink Identity: Must be a SecretKeySpec
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.SecretKeySpec"
  
  # We accept either the standard class creator (constructor) or the factory method 'create'
  # as seen in the provided evidence for violating cases.
  sink_identity_match(f)

  # 2. Material Provenance: Must be non-empty and strictly compile-time fixed
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds {
    kind == "literal"
  }

  # 3. Value Evidence: Ensure actual values are present
  values := object.get(f, "origin_values", [])
  count(values) > 0
}

# Support for both constructor and factory method sinks
sink_identity_match(f) if {
  object.get(f, "sink_node_type", "") == "class_creator"
  object.get(f, "sink_member", "") == "SecretKeySpec"
}

sink_identity_match(f) if {
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_member", "") == "create"
}

# A key is safe if it is provisioned at runtime.
# This is evidenced by the presence of any origin kind other than 'literal'
# (e.g., 'parameter', 'field', 'generated', 'call_result').
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