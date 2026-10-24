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

# Helper to get a boolean field, defaulting to false.
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

# Retrieve the fact type if present.
fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

# Core condition: path construction includes any non‑literal origin kind.
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some k in origin_kinds
  k != "literal"
}

# Allowed context: all origins are literal.
allowed_context(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  every k in origin_kinds { not k != "literal" }
}

# A fact is a violation when it meets the core condition and is not allowed.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: normalize violating facts into a standard structure.
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := object.get(f, "severity", severity)
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

# Human‑readable deny messages for each finding.
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}