package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f | f := data.drivers.cwe89_facts.facts[_] ]

# Small boolean-field helper (unused but kept for compatibility)
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

# Core violation logic: any origin kind that is not a literal indicates a runtime‑derived value
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some kind in origin_kinds
  kind != "literal"
}

# Safe contexts – none defined for this policy
allowed_context(f) if { false }

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings construction
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls  := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line])

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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}