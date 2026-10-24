package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded cryptographic key material used in SecretKeySpec construction."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard that ensures origin_kinds consists only of the literal terminal kind
guard_origin_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every kind in kinds { kind == "literal" }
}

# Guard that ensures origin_values is a non‑empty array of non‑empty strings
guard_origin_values(f) if {
  vals := object.get(f, "origin_values", [])
  is_array(vals)
  count(vals) > 0
  every v in vals { is_string(v); v != "" }
}

# Guard that excludes facts where key is consumed by a runtime init call
guard_runtime_consumer(f) if {
  key_consumer := object.get(f, "key_consumer_ast_id", 0)
  key_consumer != 0
}

# Core positive condition
core_positive_condition(f) if {
  guard_origin_kinds(f)
  guard_origin_values(f)
  sink := object.get(f, "sink_member", "")
  sink == "SecretKeySpec"
  node := object.get(f, "sink_node_type", "")
  node == "class_creator"
  resolved := object.get(f, "sink_resolved_type", "")
  resolved == "javax.crypto.spec.SecretKeySpec"
}

# is_violation
is_violation(f) if {
  core_positive_condition(f)
  not guard_runtime_consumer(f)
}

# allowed_context (none)
allowed_context(f) if {
  false
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := severity
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink_member", "")

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