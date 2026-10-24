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

# Helper: at least one origin kind is not "literal"
has_non_literal_kind(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}

# Helper: at least one origin value appears to be runtime‑derived
has_runtime_value(f) if {
  values := object.get(f, "origin_values", [])
  some v in values
  not startswith(v, "/")
  not startswith(v, "'")
}

core_positive_condition(f) if {
  has_non_literal_kind(f)
  has_runtime_value(f)
}

# Guard: all origins are literals (safe)
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds {
    k == "literal"
  }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
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

    "file":   file,
    "class":  cls,
    "method": method,
    "line":   line,
    "fact_type": ftype,
    "sink":   sink,
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