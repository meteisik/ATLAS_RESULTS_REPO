package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key‑material provenance so the policy layer can detect hard‑coded effective keys."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Core positive condition: all origin_kinds are literal, origin_values non‑empty,
# and sink characteristics match the SecretKeySpec construction.
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "crypto_key_material_fact"

  sink_member := object.get(f, "sink_member", "")
  sink_member == "create"

  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"

  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "javax.crypto.spec.SecretKeySpec"

  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }

  values := object.get(f, "origin_values", [])
  count(values) > 0
}

# Safe context guard: any origin_kinds entry that is not literal indicates
# runtime‑derived key material and should be excluded from findings.
safe_guard(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  some k in kinds
  k != "literal"
}

allowed_context(f) if {
  safe_guard(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
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