package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can easily detect hard-coded effective keys."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

#
# Guard that detects runtime‑provided key material.
#
guard_runtime_provided(f) if {
  some kind in f.origin_kinds
  kind != "literal"
}

#
# Core positive condition: only literal origins and non‑empty values,
# and required sink fields are present.
#
core_positive_condition(f) if {
  f.fact_type == "crypto_key_material_fact"
  count(f.origin_kinds) == 1
  f.origin_kinds[0] == "literal"
  count(f.origin_values) > 0
  f.sink_member != ""
  f.sink_node_type != ""
  f.sink_resolved_type != ""
}

#
# A fact is a violation when it satisfies the core positive condition
# and is not guarded as runtime‑provided.
#
is_violation(f) if {
  core_positive_condition(f)
  not guard_runtime_provided(f)
}

#
# Findings: normalize violating facts into a standard structure.
#
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

#
# Deny messages for each finding.
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}