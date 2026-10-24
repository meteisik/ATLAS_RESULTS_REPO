package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath expressions constructed from externally controlled input. Each XPath evaluation site emits a fact; this policy flags expressions whose provenance includes runtime input."

# The driver that provides facts for this policy
driver_key := "cwe643_facts"

# Primary fact type for this policy
primary_fact_type := "xpath_query_fact"

# Canonical fact list
driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Helper: check if a list contains a specific value
contains_value(list, val) := true if {
  some v in list
  v == val
}

# Core positive condition: fact originates from runtime input
core_positive_condition(f) if {
  contains_value(object.get(f, "origin_kinds", []), "call_result")
  contains_value(object.get(f, "origin_values", []), "getenv")
}

# No allowed context rule; safe facts will not satisfy core_positive_condition
allowed_context(f) if {
  false
}

# Violation rule
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
findings := [v |
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

  v := {
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