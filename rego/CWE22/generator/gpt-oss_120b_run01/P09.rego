package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Core positive condition: any non‑literal origin kind
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}
# Core positive condition: any origin value not the constant literal
core_positive_condition(f) if {
  vals := object.get(f, "origin_values", [])
  some v in vals
  v != "/home/user/uploads/"
}

# Guard: all origins are literals
guard_all_literal_origins(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

# Guard: all origin values are the compile‑time constant
guard_literal_only_values(f) if {
  vals := object.get(f, "origin_values", [])
  count(vals) > 0
  every v in vals { v == "/home/user/uploads/" }
}

# Allowed (safe) context
allowed_context(f) if {
  guard_all_literal_origins(f)
}
allowed_context(f) if {
  guard_literal_only_values(f)
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Classification helper
classification(f) = "VIOLATION" if {
  is_violation(f)
}
classification(f) = "SAFE" if {
  not is_violation(f)
}

# Findings: only violations
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink  := object.get(f, "sink", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
    "classification": classification(f)
  }
]

# Human‑readable deny messages for each finding
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