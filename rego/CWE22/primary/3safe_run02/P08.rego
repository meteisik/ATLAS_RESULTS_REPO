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

# Helper to fetch a list field with a default
getlist(o, k) := l if {
  l := object.get(o, k, [])
}

# Core positive condition: path contains a runtime call result and a getenv value
core_positive_condition(f) if {
  kinds := getlist(f, "origin_kinds")
  values := getlist(f, "origin_values")
  some k in kinds
  k != "literal"
  some v in values
  v == "getenv"
}

# Guard to ensure all kinds are literal (no call_result)
guard_safe_literal_kinds(f) if {
  kinds := getlist(f, "origin_kinds")
  every k in kinds { k == "literal" }
}

# Guard to ensure all values are static literals (no getenv)
guard_safe_static_values(f) if {
  values := getlist(f, "origin_values")
  every v in values { v != "getenv" }
}

# Safe context if both guards pass
allowed_context(f) if {
  guard_safe_literal_kinds(f)
  guard_safe_static_values(f)
}

# A fact is a violation if it matches the core positive condition and is not in a safe context
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink_member", ""),
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [policy_id, title, file, line])
}