package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can detect hard‑coded effective keys."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard: any origin kind that is not literal indicates safe material.
guard_safe_origin_kinds(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some kind in origin_kinds
  kind != "literal"
}

# Safe context: facts that have non‑literal origin kinds.
allowed_context(f) if {
  guard_safe_origin_kinds(f)
}

# Core positive condition: all conditions for a violation.
core_positive_condition(f) if {
  # origin_kinds must contain only the literal kind
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) == 1
  kind := origin_kinds[0]
  kind == "literal"

  # origin_values must be non‑empty
  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
  every val in origin_values { val != "" }

  # sink checks
  sink_member := object.get(f, "sink_member", "")
  sink_member == "PBEKeySpec"
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "class_creator"
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "javax.crypto.spec.PBEKeySpec"
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}