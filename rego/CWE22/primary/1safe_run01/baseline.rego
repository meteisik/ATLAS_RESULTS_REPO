package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_facts := [f | f := data.drivers.cwe22_facts.facts[_]]

# Helper to test if a value exists in a list field of a fact
has_value_in_list(f, field, val) if {
  some v in object.get(f, field, [])
  v == val
}

has_call_result(f) if { has_value_in_list(f, "origin_kinds", "call_result") }
has_getenv(f) if { has_value_in_list(f, "origin_values", "getenv") }

# Core positive condition: both call_result and getenv present
core_positive_condition(f) if {
  has_call_result(f)
  has_getenv(f)
}

# Guard for safe paths: no call_result and no getenv in origins
safe_literal_path_guard(f) if {
  not has_call_result(f)
  every v in object.get(f, "origin_values", []) { v != "getenv" }
}

# A fact is a violation if it satisfies the core condition and is not guarded as safe
is_violation(f) if {
  core_positive_condition(f)
  not safe_literal_path_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

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
    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink", ""),
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