package policies.cwe643
import rego.v1

# Policy metadata
policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath queries built from runtime values such as environment variables."

# Driver facts key
driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

# Canonical fact list
driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Core violation logic
core_positive_condition(f) if {
  # Fact type matches
  object.get(f, "fact_type", "") == "xpath_query_fact"

  # Presence of a call_result origin kind
  some kind in object.get(f, "origin_kinds", [])
  kind == "call_result"

  # Presence of a getenv origin value
  some val in object.get(f, "origin_values", [])
  val == "getenv"
}

# Allowed contexts (none for this policy)
allowed_context(f) if {
  false
}

# Predicate for violation
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings construction
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

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