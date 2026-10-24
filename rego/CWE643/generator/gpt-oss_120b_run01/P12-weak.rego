package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy layer can detect expressions built from externally controlled input."

primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Core positive condition: at least one origin is non‑literal and its corresponding value looks like a runtime identifier.
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(values) == count(kinds)

  some i
  i >= 0
  i < count(kinds)

  kind := kinds[i]
  kind != "literal"

  value := values[i]
  regex.match("^[A-Za-z_][A-Za-z0-9_]*$", value)
}

# Guard rule: all origins are literals and all values are compile‑time constants (no identifier‑like strings).
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds {
    k == "literal"
  }

  values := object.get(f, "origin_values", [])
  every v in values {
    not regex.match("^[A-Za-z_][A-Za-z0-9_]*$", v)
  }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Violation findings
violation_findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  finding := {
    "policy_id":       policy_id,
    "title":           title,
    "severity":        severity,
    "description":    description,
    "file":            file,
    "class":           cls,
    "method":          method,
    "line":            line,
    "classification":  "VIOLATION",
    "sink":            object.get(f, "sink_member", ""),
    "fact_type":       object.get(f, "fact_type", ""),
  }
]

# Safe findings (guarded)
safe_findings := [finding |
  f := driver_facts[_]
  allowed_context(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  finding := {
    "policy_id":       policy_id,
    "title":           title,
    "severity":        severity,
    "description":    description,
    "file":            file,
    "class":           cls,
    "method":          method,
    "line":            line,
    "classification":  "SAFE",
    "sink":            object.get(f, "sink_member", ""),
    "fact_type":       object.get(f, "fact_type", ""),
  }
]

findings := array.concat(violation_findings, safe_findings)

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