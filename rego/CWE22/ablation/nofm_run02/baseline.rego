package policies.cwe22
import rego.v1

# Policy metadata
policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

# Driver key this policy consumes facts from.
driver_key := "cwe22_facts"

# Primary fact type for this policy
primary_fact_type := "file_path_fact"

# Canonical fact list for this policy
driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Guard rule: detect paths that are purely literal (safe)
literal_only_origin_guard(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_kinds == ["literal"]
  origin_values := object.get(f, "origin_values", [])
  every v in origin_values { v != "getenv" }
}

# Allowed context: safe paths
allowed_context(f) if {
  literal_only_origin_guard(f)
}

# Core condition: path includes a runtime-derived origin
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some k in origin_kinds
  k == "call_result"
  origin_values := object.get(f, "origin_values", [])
  some v in origin_values
  v == "getenv"
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: normalize violating facts
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

# Human-readable deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}