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

#
# Core positive condition: path contains a runtime call result and a getenv value
#
core_positive_condition(f) if {
  kinds := getlist(f, "origin_kinds")
  values := getlist(f, "origin_values")
  some k in kinds
  k == "call_result"
  some v in values
  v == "getenv"
}

#
# Guard to ensure all origin_kinds are 'literal'
#
guard_literal_only_origins(f) if {
  kinds := getlist(f, "origin_kinds")
  every k in kinds { k == "literal" }
}

#
# Guard to ensure no runtime sources in kinds or values
#
guard_no_runtime_sources(f) if {
  kinds := getlist(f, "origin_kinds")
  values := getlist(f, "origin_values")
  every k in kinds { not k == "call_result" }
  every v in values { not v == "getenv" }
}

#
# Safe context if both guards pass
#
allowed_context(f) if {
  guard_literal_only_origins(f)
  guard_no_runtime_sources(f)
}

#
# A fact is a violation if it matches the core condition and is not in a safe context
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings: normalize violating facts into a standard structure
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
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

#
# Human‑readable denial messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [policy_id, title, file, line])
}