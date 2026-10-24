package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects hard‑coded effective cryptographic keys by ensuring all key material originates from literal constants."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Helper: all origin_kinds are "literal"
all_literal_kinds(f) if {
  every kind in f.origin_kinds {
    kind == "literal"
  }
}

# Helper: origin_values list is non‑empty and contains only non‑empty strings
all_nonempty_origin_values(f) if {
  count(f.origin_values) > 0
  every val in f.origin_values {
    val != ""
  }
}

# Guard: fail if any origin_kind is not "literal"
guard_origin_kinds_runtime(f) if {
  some kind in f.origin_kinds
  kind != "literal"
}

# Guard: fail if origin_values list is empty or contains an empty string
guard_origin_values_runtime(f) if {
  count(f.origin_values) == 0
}
guard_origin_values_runtime(f) if {
  some val in f.origin_values
  val == ""
}

# Core positive condition: all literal kinds and all non‑empty origin values
core_positive_condition(f) if {
  all_literal_kinds(f)
  all_nonempty_origin_values(f)
}

# A fact is a violation only if it satisfies the core condition and does not hit any guard
is_violation(f) if {
  core_positive_condition(f)
  not guard_origin_kinds_runtime(f)
  not guard_origin_values_runtime(f)
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