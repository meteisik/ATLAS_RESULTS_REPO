package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Helper: all origin kinds are literal
all_kinds_literal(f) if {
  every kind in f.origin_kinds { kind == "literal" }
}

# Helper: all origin values are literal paths (start with '/')
all_values_literal_path(f) if {
  every val in f.origin_values { regex.match("^/.*", val) }
}

# Safe path guard: all origins are literal and all values are literal paths
safe_path_guard(f) if {
  all_kinds_literal(f)
  all_values_literal_path(f)
}

# Core positive condition: any non‑literal origin kind
core_positive_condition_non_literal_kind(f) if {
  some kind in f.origin_kinds
  kind != "literal"
}

# Core positive condition: any runtime origin value (non‑path)
core_positive_condition_runtime_value(f) if {
  some val in f.origin_values
  not regex.match("^/.*", val)
}

# Combine core conditions
core_positive_condition(f) if {
  core_positive_condition_non_literal_kind(f)
}
core_positive_condition(f) if {
  core_positive_condition_runtime_value(f)
}

# Allowed context: safe paths
allowed_context(f) if {
  safe_path_guard(f)
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := ""
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink_member", "")

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
    v.policy_id,
    v.title,
    file,
    line,
  ])
}