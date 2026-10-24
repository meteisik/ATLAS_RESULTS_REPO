package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := `Describe cryptographic key-material provenance so the policy layer can detect
hard-coded effective keys.`

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

#
# Core violation logic
#
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "crypto_key_material_fact"

  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  all_literal(kinds)

  values := object.get(f, "origin_values", [])
  count(values) > 0

  object.get(f, "sink_member", "") == "DESedeKeySpec"
  object.get(f, "sink_node_type", "") == "class_creator"
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.DESedeKeySpec"
}

all_literal(kinds) if {
  every kind in kinds { kind == "literal" }
}

#
# Optional safe context rule – always false for this policy
#
allowed_context(f) if false

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings
#
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line     := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name   := object.get(f, "method_name", "")
  method_id     := object.get(f, "method_id", 0)
  call_ast_id   := object.get(f, "call_ast_id", 0)
  sink          := object.get(f, "sink", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,

    "file":        file_raw,
    "span":        span_raw,

    "fact_type":   fact_type_val,
    "method_name": method_name,
    "method_id":   method_id,
    "call_ast_id": call_ast_id,

    "sink":        sink,
  }
]

#
# Human‑readable deny messages
#
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  span := object.get(v, "span", {})
  start := object.get(span, "start", {})
  line := object.get(start, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id,
    v.title,
    file,
    line,
  ])
}