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

# All origins must be literal
all_lit_origins(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds { k == "literal" }
}

# No sanitizer transform present
no_sanitizer(f) if {
  transforms := object.get(f, "transform_call_names", [])
  count(transforms) == 0
}

core_positive_condition(f) if {
  all_lit_origins(f)
  no_sanitizer(f)
}

# Safe logs: call_result origin and sanitizer transform
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  transforms := object.get(f, "transform_call_names", [])
  some k in kinds; k == "call_result"
  some t in transforms; t == "sanitize"
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line     := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name   := object.get(f, "method_name", "")
  method_id     := object.get(f, "method_id", 0)
  call_ast_id   := object.get(f, "call_ast_id", 0)

  sink := object.get(f, "sink", "")

  finding := {
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