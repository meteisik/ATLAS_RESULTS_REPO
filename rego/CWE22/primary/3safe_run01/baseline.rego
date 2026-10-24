package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file path constructions that incorporate externally provided input, potentially leading to path traversal vulnerabilities."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Helper to determine if any origin value is a runtime value (not a literal path)
has_runtime_value(f) if {
  some val in f.origin_values
  not regex.match("^/.*", val)
}

# Helper to ensure all origin kinds are literal
all_kinds_literal(f) if {
  every kind in f.origin_kinds { kind == "literal" }
}

# Helper to ensure all origin values are literal paths
all_values_literal_path(f) if {
  every val in f.origin_values { regex.match("^/.*", val) }
}

# Safe literal path guard
safe_literal_path(f) if {
  all_kinds_literal(f)
  all_values_literal_path(f)
}

# Allowed context rule: paths that are entirely literal are safe
allowed_context(f) if {
  safe_literal_path(f)
}

# Core positive condition: at least one non‑literal origin kind AND at least one runtime origin value
core_positive_condition(f) if {
  some kind in f.origin_kinds
  kind != "literal"
  has_runtime_value(f)
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := ""

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

# Human‑readable denial messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}