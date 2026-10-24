package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

#
# Helper predicates
#
has_non_literal_kind(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  some k in kinds
  k != "literal"
}

has_runtime_value(f) if {
  vals := object.get(f, "origin_values", [])
  count(vals) > 0
  some v in vals
  v == "getenv"
}

has_all_literal(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

allowed_context(f) if {
  has_all_literal(f)
  not has_runtime_value(f)
}

core_positive_condition(f) if {
  has_non_literal_kind(f)
  has_runtime_value(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings
#
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
  }
]

#
# Deny messages
#
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