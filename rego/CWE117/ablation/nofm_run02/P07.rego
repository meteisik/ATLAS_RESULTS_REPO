package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detects log messages that include runtime-provided data without CR/LF neutralization."

driver_key := "cwe117_facts"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# helper: true if all kinds are "literal"
all_literal(kinds) if {
  every kind in kinds { kind == "literal" }
}

# helper: neutralizing transformation names
neutralizer(name) if {
  name == "replace"
}
neutralizer(name) if {
  name == "replaceAll"
}
neutralizer(name) if {
  name == "trim"
}

# guard: safe when all origins are literal and no neutralizer applied
safe_literal_no_transform(f) if {
  kinds := object.get(f, "origin_kinds", [])
  names := object.get(f, "transform_call_names", [])
  count(names) == 0
  all_literal(kinds)
}

# guard: safe when a runtime origin is present but a neutralizer is applied
safe_neutralized_runtime(f) if {
  kinds := object.get(f, "origin_kinds", [])
  names := object.get(f, "transform_call_names", [])
  some kind in kinds
    kind != "literal"
  some name in names
    neutralizer(name)
}

allowed_context(f) if { safe_literal_no_transform(f) }
allowed_context(f) if { safe_neutralized_runtime(f) }

# core violation condition
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  names := object.get(f, "transform_call_names", [])
  count(names) == 0
  some idx
    count(kinds) > idx
    count(vals) > idx
    kinds[idx] == "call_result"
    vals[idx] != "Login attempt for user "
    vals[idx] != "getenv"
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))
  sev := object.get(f, "severity", severity)
  sink_ast_id := object.get(f, "sink_ast_id", 0)

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "sink_ast_id": sink_ast_id,
    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink", "")
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