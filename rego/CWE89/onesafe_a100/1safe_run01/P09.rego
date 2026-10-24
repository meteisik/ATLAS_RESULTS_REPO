package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input."

# Driver facts for this policy
driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# Helper to check for a non‑literal origin kind
has_non_literal_origin(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

# Core positive condition: a fact is potentially a violation if
#   - it has at least one non‑literal origin kind
#   - it contains origin_values
#   - it targets a java.sql.Statement executeQuery call
core_positive_condition(f) if {
  has_non_literal_origin(f)
  vals := object.get(f, "origin_values", [])
  count(vals) > 0
  object.get(f, "sink_member", "") == "executeQuery"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.Statement"
}

# No allowlist – all facts that satisfy the core condition are violations
allowed_context(f) if { false }

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
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
    policy_id, cls, method, line])

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

# Human‑readable deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}