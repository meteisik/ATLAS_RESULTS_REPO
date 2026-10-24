package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detects log messages that include runtime-provided data without CR/LF neutralization."

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# Helper: check that origin_kinds contains a call_result and its corresponding origin_value is non-empty
contains_call_result(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(vals) > 0
  some i
  i < count(kinds)
  kinds[i] == "call_result"
  val := vals[i]
  val != ""
}

# Helper: check that there are no neutralizing transforms applied
no_neutralizer(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) == 0
}

# Helper: check that a neutralizing transform is present
allowed_context(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) > 0
}

# Core positive condition: call_result origin with runtime value and no neutralizer
core_positive_condition(f) if {
  contains_call_result(f)
  no_neutralizer(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls  := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := severity
  ftype := object.get(f, "fact_type", "")
  sink := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}