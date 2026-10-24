package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Detect SQL statements whose text is built from runtime‑derived input (environment reads, request parameters, etc.) rather than being composed solely of compile‑time literals."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

# Canonical fact list from the driver
driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# Core positive condition: fact must be of the correct type and contain
# non‑empty origin_kinds and origin_values arrays.
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "sql_query_fact"

  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0

  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
}

# Guard rule: all origins are literals → safe context.
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds {
    kind == "literal"
  }
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: normalized structure for each violating fact
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink_member", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,

    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,

    # Preserve useful identifiers for downstream tooling
    "sink_ast_id":          object.get(f, "sink_ast_id", 0),
    "method_id":            object.get(f, "method_id", 0),
    "receiver_decl_name":   object.get(f, "receiver_decl_name", ""),
    "query_arg_ast_id":     object.get(f, "query_arg_ast_id", 0),
  }
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