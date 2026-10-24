package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

# Facts produced by the driver for this policy.
driver_facts := [f | f := data.drivers.cwe117_facts.facts[_]]

# Helper: check if a list contains a value.
contains_value(list, val) := true if { val in list }

# Core violation logic
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  "call_result" in kinds
  "getenv" in values
}

# Guard: safe if all origins are literal and non‑empty
safe_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  kinds == ["literal"]
  every v in values { v != "" }
}

# Guard: safe if a neutralizing transformation was applied
safe_neutralized_runtime(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) > 0
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_literal_only(f)
  not safe_neutralized_runtime(f)
}

# Findings: normalize violating facts
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line     := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name   := object.get(f, "method_name", "")
  method_id     := object.get(f, "method_id", 0)
  call_ast_id   := object.get(f, "sink_ast_id", 0)

  sink := object.get(f, "sink", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file_raw,
    "span":        span_raw,
    "fact_type":   fact_type_val,
    "method_name": method_name,
    "method_id":   method_id,
    "call_ast_id": call_ast_id,
    "sink":        sink,
  }
]

# Human‑readable denial messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  span := object.get(v, "span", {})
  start := object.get(span, "start", {})
  line := object.get(start, "line", 0)
  method := object.get(v, "method_name", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}