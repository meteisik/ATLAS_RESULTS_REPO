package policies.cwe89
import rego.v1

# Policy metadata
policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input."

# Driver key this policy consumes facts from.
driver_key := "cwe89_facts"

# Primary fact type
primary_fact_type := "sql_query_fact"

# Canonical fact list for this policy
driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# Helpers to retrieve list fields
origin_kinds(f) := kinds if {
  kinds := object.get(f, "origin_kinds", [])
}
origin_values(f) := vals if {
  vals := object.get(f, "origin_values", [])
}

# Core positive condition: presence of non‑literal origin and a runtime value
contains_non_literal(f) if {
  kinds := origin_kinds(f)
  some k in kinds
  k != "literal"
}
contains_runtime_value(f) if {
  vals := origin_values(f)
  some v in vals
  not contains(v, " ")
}
core_positive_condition(f) if {
  contains_non_literal(f)
  contains_runtime_value(f)
}

# Allowed context: all origins are literals (safe)
allowed_context(f) if {
  kinds := origin_kinds(f)
  every k in kinds { k == "literal" }
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: normalize violating facts into a standard structure
findings := [finding |
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

# Human‑readable denial messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}