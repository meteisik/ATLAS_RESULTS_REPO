package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath queries built from runtime values such as environment variables."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Helper: all origin kinds are literal
guard_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds { kind == "literal" }
}

# Helper: all origin values are compile-time constants (assumed when kinds are literal)
guard_allowed_values(f) if {
  guard_literal_only(f)
}

# Allowed contexts: facts that pass both guards
allowed_context(f) if {
  guard_literal_only(f)
  guard_allowed_values(f)
}

# Core condition: at least one non‑literal origin kind with a non‑empty value
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(values) > 0
  some i; i < count(kinds); kind := kinds[i]; kind != "literal"; val := values[i]; val != ""
}

# A fact is a violation when it meets the core condition and is not in an allowed context
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}