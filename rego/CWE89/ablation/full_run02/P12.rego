package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detect SQL queries constructed from runtime data that are executed via Statement.executeQuery."

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# Guard: detect any origin kind that is not a literal.
guard_violation_origin_kind(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

# Guard: accept facts only when all origin kinds are literal and all origin values are not "getenv".
guard_safe_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  every kind in kinds { kind == "literal" }
  every val in values { val != "getenv" }
}

# Core positive condition: a fact is potentially violating when it has a non‑literal origin kind
# and its origin values contain a runtime value such as "getenv".
core_positive_condition(f) if {
  guard_violation_origin_kind(f)
  values := object.get(f, "origin_values", [])
  some val in values
  val == "getenv"
}

# Allowed context: facts that satisfy the safe guard.
allowed_context(f) if {
  guard_safe_literal_only(f)
}

# A fact is a violation when it satisfies the core positive condition and is not in an allowed context.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)

  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink_member", "")

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
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