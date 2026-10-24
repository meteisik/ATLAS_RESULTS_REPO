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

# Helper to test if a value exists in a list field of a fact
has_value_in_list(f, field, val) if {
  some v in object.get(f, field, [])
  v == val
}

has_call_result(f) if { has_value_in_list(f, "origin_kinds", "call_result") }
has_getenv(f) if { has_value_in_list(f, "origin_values", "getenv") }

# Core positive condition: a fact is potentially violating if it contains
# any non‑literal origin kind and a non‑literal origin value
core_positive_condition(f) if {
  has_call_result(f)
  has_getenv(f)
}

# Guard for safe paths: all origin kinds are literal and no runtime value
guard_literal_only_origins(f) if {
  not has_call_result(f)
  every v in object.get(f, "origin_values", []) { v != "getenv" }
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_literal_only_origins(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
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