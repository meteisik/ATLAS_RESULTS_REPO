package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detect SQL queries that incorporate runtime‑provided values, indicating potential SQL injection."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

# Canonical list of driver facts
driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# Guard: all origin kinds are literal
guard_all_literal_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

# Guard: all origin values are non‑empty (covers literal values)
guard_all_literal_values(f) if {
  values := object.get(f, "origin_values", [])
  count(values) > 0
  every v in values { v != "" }
}

# Allowed (safe) context: both guards succeed
allowed_context(f) if {
  guard_all_literal_kinds(f)
  guard_all_literal_values(f)
}

# Core positive condition: at least one non‑literal origin kind
# and the corresponding origin value is present (runtime‑derived)
core_positive_condition(f) if {
  some i
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  k := kinds[i]
  v := values[i]
  k != "literal"
  v != ""
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: include all original fact fields plus policy metadata
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)

  v := object.union(f, {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "line":        line,
  })
]

# Human‑readable deny messages
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