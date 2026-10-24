package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detects log messages that include runtime-provided data without CR/LF neutralization."

driver_facts := [f | f := data.drivers.cwe117_facts.facts[_]]

# Helper: check that a list contains a specific value
contains_value(l, v) if {
  some x in l
  x == v
}

# Helper: check that a list is empty
empty_list(l) if {
  count(l) == 0
}

# Core positive condition: violation if a call_result origin exists, no transformation, and origin_values non-sentinel
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  contains_value(kinds, "call_result")

  names := object.get(f, "transform_call_names", [])
  empty_list(names)

  vals := object.get(f, "origin_values", [])
  some v in vals
  v != ""
}

# Guard: safe literal only (all origins literal, no transformation)
safe_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds { k == "literal" }

  names := object.get(f, "transform_call_names", [])
  empty_list(names)
}

# Guard: safe neutralizing transformation (any sanitizer present)
safe_neutralizing_transformation(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replace"
}
safe_neutralizing_transformation(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replaceAll"
}
safe_neutralizing_transformation(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "trim"
}

# Allowed context: either guard holds
allowed_context(f) if {
  safe_literal_only(f)
}
allowed_context(f) if {
  safe_neutralizing_transformation(f)
}

# Violation definition
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := ""
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
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

# Deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}