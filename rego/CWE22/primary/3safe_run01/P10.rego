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

# Guard: only consider file creation sinks
class_creator_file_sink_guard(f) if {
  f.sink_node_type == "class_creator"
  f.sink_member == "File"
}

# Helper: check for a call_result origin
has_call_result(f) if {
  some kind in f.origin_kinds
  kind == "call_result"
}

# Helper: check for a non‑literal runtime origin value (e.g., getenv)
has_runtime_value(f) if {
  some val in f.origin_values
  not regex.match("^/.*", val)
}

# Helper: all kinds are literal
all_kinds_literal(f) if {
  every kind in f.origin_kinds { kind == "literal" }
}

# Helper: all values are literal paths
all_values_literal_path(f) if {
  every val in f.origin_values { regex.match("^/.*", val) }
}

# Safe context: entirely literal path
safe_literal_path(f) if {
  all_kinds_literal(f)
  all_values_literal_path(f)
}

# Allowed context: safe literal paths
allowed_context(f) if {
  safe_literal_path(f)
}

# Core positive condition: discriminators per plan
core_positive_condition(f) if {
  has_call_result(f)
  has_runtime_value(f)
}

# Violation predicate
is_violation(f) if {
  class_creator_file_sink_guard(f)
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,

    "file":        file,
    "method":      method,
    "line":        line,

    "fact_type":   object.get(f, "fact_type", ""),
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
    "sink_member": object.get(f, "sink_member", ""),
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