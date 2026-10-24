package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input."

#
# Canonical fact list for this policy
#
driver_facts := [f | f := data.drivers.cwe89_facts.facts[_]]

#
# Guard: ensure fact represents a JDBC executeQuery sink
#
sink_check(f) if {
  object.get(f, "sink_member", "") == "executeQuery"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "java.sql.Statement"
}

#
# Core violation condition: any non‑literal origin kind indicates a runtime‑derived value
#
core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some kind in origin_kinds
  kind != "literal"
}

#
# Safe context: all origins are literal
#
allowed_context(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  every kind in origin_kinds { kind == "literal" }
}

#
# Violation predicate
#
is_violation(f) if {
  sink_check(f)
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings construction
#
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev   := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink  := object.get(f, "sink", "")

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
    "sink":        sink
  }
]

#
# Human‑readable denial messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line])
}