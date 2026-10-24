package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detect hard‑coded effective cryptographic keys by analysing key‑material provenance."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

# Facts emitted by the driver.
driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# -------------------------------------------------------------------
# Guard rules – mark a fact as safe (allowed context)
# -------------------------------------------------------------------
guard_non_literal_origin_kind(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some kind in origin_kinds
  kind != "literal"
}

guard_empty_origin_kinds(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) == 0
}

guard_key_consumer_ast_id_sentinel(f) if {
  key_consumer_ast_id := object.get(f, "key_consumer_ast_id", 0)
  key_consumer_ast_id == 0

  origin_kinds := object.get(f, "origin_kinds", [])
  # safe when there are no literal origins
  count(origin_kinds) == 0
  # or when any origin kind is not literal (already covered by other guard,
  # but kept for completeness)
  some kind in origin_kinds
  kind != "literal"
}

# A fact is in an allowed (safe) context if any guard fires.
allowed_context(f) if {
  guard_non_literal_origin_kind(f)
}
allowed_context(f) if {
  guard_empty_origin_kinds(f)
}
allowed_context(f) if {
  guard_key_consumer_ast_id_sentinel(f)
}

# -------------------------------------------------------------------
# Core positive condition – when the fact represents a hard‑coded key
# -------------------------------------------------------------------
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "crypto_key_material_fact"

  # origin_kinds must be present and every element must be "literal"
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every kind in origin_kinds {
    kind == "literal"
  }

  # origin_values must be present and every element non‑empty
  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
  every v in origin_values {
    v != ""
  }
}

# -------------------------------------------------------------------
# Violation predicate
# -------------------------------------------------------------------
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# -------------------------------------------------------------------
# Findings – normalized output for downstream tools
# -------------------------------------------------------------------
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", "")

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
    "sink":        object.get(f, "sink", ""),
  }
]

# -------------------------------------------------------------------
# Deny – human‑readable messages
# -------------------------------------------------------------------
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