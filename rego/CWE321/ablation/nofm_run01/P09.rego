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

# All origin kinds must be the literal kind
core_positive_condition(f) if {
  # Ensure the array exists and is non-empty
  count(f.origin_kinds) > 0
  # All kinds are "literal"
  every kind in f.origin_kinds {
    kind == "literal"
  }
  # All origin values are non-empty strings
  count(f.origin_values) > 0
  every val in f.origin_values {
    val != ""
  }
}

# The key is considered safe if it is consumed at runtime
guard_safe_if_consumer_present(f) if {
  f.key_consumer_ast_id != 0
}

is_violation(f) if {
  object.get(f, "fact_type", "") == "crypto_key_material_fact"
  core_positive_condition(f)
  not guard_safe_if_consumer_present(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id,
    cls,
    method,
    line,
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
    v.policy_id,
    v.title,
    file,
    line,
  ])
}