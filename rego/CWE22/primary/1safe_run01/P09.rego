package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

#
# Helper to test if any origin_kind is not literal
#
has_non_literal_kind(f) if {
  some k in object.get(f, "origin_kinds", [])
  k != "literal"
}

#
# Core positive condition: at least one non‑literal origin
#
core_positive_condition(f) if {
  has_non_literal_kind(f)
}

#
# Guard for safe literal paths: all origin_kinds are literal
#
safe_literal_path(f) if {
  every k in object.get(f, "origin_kinds", []) { k == "literal" }
}

#
# Allow context: safe literal paths
#
allowed_context(f) if {
  safe_literal_path(f)
}

#
# A fact is a violation if it meets the core condition and is not in an allowed context
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# findings: normalize violating facts into a standard structure
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
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
# deny: human-readable messages for each finding
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}