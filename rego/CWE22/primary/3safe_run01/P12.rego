package policies.cwe22
import rego.v1

# Policy metadata
policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file path constructions that incorporate externally provided input, potentially leading to path traversal vulnerabilities."

# Driver facts source
driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

# Canonical fact list for this policy
driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Helper predicates

# True if the fact contains a call_result origin kind
has_call_result(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind == "call_result"
}

# True if the fact contains a runtime-derived origin value (non‑literal path)
has_runtime_value(f) if {
  some val in object.get(f, "origin_values", [])
  not regex.match("^/.*", val)
}

# True if all origin kinds are literal
all_kinds_literal(f) if {
  every kind in object.get(f, "origin_kinds", []) {
    kind == "literal"
  }
}

# True if all origin values are literal paths
all_values_literal(f) if {
  every val in object.get(f, "origin_values", []) {
    regex.match("^/.*", val)
  }
}

# Safe guard: true when the path is composed only of literal origins
safe_origin_guard(f) if {
  all_kinds_literal(f)
  all_values_literal(f)
}

# Core positive condition: path construction uses a call_result origin and a runtime value
core_positive_condition(f) if {
  has_call_result(f)
  has_runtime_value(f)
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not safe_origin_guard(f)
}

# Findings: normalize violating facts into a standard structure
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink", "")

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

    # Additional context from the fact
    "sink_node_type":   object.get(f, "sink_node_type", ""),
    "sink_member":      object.get(f, "sink_member", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
  }
]

# Human‑readable denial messages for each finding
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}