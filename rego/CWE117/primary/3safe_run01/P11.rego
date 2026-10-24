package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# Helper to test if a list contains a value
contains_value(list, val) := true if {
  some v in list
  v == val
}

# Core positive condition: log message originates from a call_result containing getenv and no neutralizing transform
core_positive_condition(f) if {
  origins := object.get(f, "origin_kinds", [])
  contains_value(origins, "call_result")
  values := object.get(f, "origin_values", [])
  contains_value(values, "getenv")
  transforms := object.get(f, "transform_call_names", [])
  count(transforms) == 0
}

# Guard rule: all origins are literals (safe)
safe_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds { k == "literal" }
}

# Guard rule: a neutralizing transform is present (safe)
safe_neutralized(f) if {
  transforms := object.get(f, "transform_call_names", [])
  count(transforms) > 0
}

# Allowed context: any guard rule matches
allowed_context(f) if {
  safe_literal_only(f)
}
allowed_context(f) if {
  safe_neutralized(f)
}

# Violation logic
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
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

# Deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}