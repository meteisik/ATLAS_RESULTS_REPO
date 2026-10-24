package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detects log messages containing externally controlled data that reach the logging sink without CR/LF-neutralizing transformation."

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# Core positive condition: at least one origin is NOT a literal constant,
# meaning runtime-provided data (parameter, call_result, field, generated,
# or unknown) flows into the log message.
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  some kind in kinds
  kind != "literal"
}

# Safe: a CR/LF-neutralizing transformation was applied between origin and sink.
allowed_context(f) if {
  transforms := object.get(f, "transform_call_names", [])
  is_array(transforms)
  count(transforms) > 0
}

# Safe: ALL origins are literal/constant terminals (no runtime-provided provenance).
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every kind in kinds {
    kind == "literal"
  }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  sink   := object.get(f, "sink_member", "")

  desc := sprintf("Externally controlled data reaches log sink %s.%s (line %v) without CR/LF neutralization", [
    cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   primary_fact_type,
    "sink":        sink,
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
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