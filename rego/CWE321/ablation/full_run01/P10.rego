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

# Helper to retrieve boolean fields, if needed
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

# Extract fact_type if present
fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

# Core violation logic
core_positive_condition(f) if {
  t := object.get(f, "fact_type", "")
  t == "crypto_key_material_fact"

  kinds := object.get(f, "origin_kinds", [])
  count(kinds) == 2
  every kind in kinds { kind == "literal" }

  vals := object.get(f, "origin_values", [])
  count(vals) == 2
  every val in vals { val != "" }

  member := object.get(f, "sink_member", "")
  member == "newInstance"

  node_type := object.get(f, "sink_node_type", "")
  node_type == "method_invocation"

  resolved := object.get(f, "sink_resolved_type", "")
  resolved == "javax.crypto.spec.SecretKeySpec"
}

# Guard rules for safe contexts
guard_safe_origin_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

guard_safe_origin_values(f) if {
  vals := object.get(f, "origin_values", [])
  some val in vals
  val == ""
}

guard_safe_sink_resolved_type(f) if {
  resolved := object.get(f, "sink_resolved_type", "")
  resolved != "javax.crypto.spec.SecretKeySpec"
}

# Allowed context: any of the safe guards true
allowed_context(f) if {
  guard_safe_origin_kinds(f)
}
allowed_context(f) if {
  guard_safe_origin_values(f)
}
allowed_context(f) if {
  guard_safe_sink_resolved_type(f)
}

# is_violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
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

# Human‑readable deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}