package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key‑material provenance so the policy layer can detect hard‑coded effective keys."

driver_key := "cwe321_facts"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

#
# Core violation logic
#
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "crypto_key_material_fact"

  sink_id := object.get(f, "sink_ast_id", 0)
  sink_id > 0

  origin_ids := object.get(f, "origin_ast_ids", [])
  count(origin_ids) > 0
  every oid in origin_ids { oid > 0 }

  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds { kind == "literal" }

  values := object.get(f, "origin_values", [])
  count(values) > 0
  every v in values { v != "" }
}

is_violation(f) if {
  core_positive_condition(f)
}

#
# Findings
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink", "")

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

#
# Human‑readable messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}