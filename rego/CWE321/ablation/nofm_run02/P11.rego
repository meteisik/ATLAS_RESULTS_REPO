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

# Core positive condition: all origin_kinds are "literal" and all origin_values are non‑empty strings.
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  is_array(kinds)
  is_array(vals)
  count(kinds) == count(vals)
  count(kinds) > 0
  every kind in kinds { kind == "literal" }
  every v in vals { is_string(v); v != "" }
}

# Guard: reject if any origin_kind is not "literal".
guard_non_literal_origin_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  some kind in kinds
  kind != "literal"
}

# Guard: if there is no consumer and any origin_kind is not "literal".
guard_no_consumer_when_non_literal(f) if {
  consumer := object.get(f, "key_consumer_ast_id", 0)
  consumer == 0
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  some kind in kinds
  kind != "literal"
}

# Optional guard: confirm constructor identity for additional confidence.
guard_confirm_sink_constructor(f) if {
  member := object.get(f, "sink_member", "")
  node := object.get(f, "sink_node_type", "")
  resolved := object.get(f, "sink_resolved_type", "")
  member == "SecretKeySpec"
  node == "class_creator"
  resolved == "javax.crypto.spec.SecretKeySpec"
}

# Safe context: none defined for this policy.
allowed_context(f) if {
  false
}

# A fact is a violation if it satisfies the core positive condition and
# passes all guard checks.
is_violation(f) if {
  core_positive_condition(f)
  not guard_non_literal_origin_kinds(f)
  not guard_no_consumer_when_non_literal(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
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