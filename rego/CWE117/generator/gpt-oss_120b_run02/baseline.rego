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

# Violation predicate: core condition must hold and no allowed (safe) context.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Core condition identifies candidates that could be violations.
core_positive_condition(f) if {
  # Fact type must be the expected one.
  fact_type := object.get(f, "fact_type", "")
  fact_type == "log_message_fact"

  # Origin information must be present (non‑sentinel).
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0

  # No neutralizing transformations present.
  t_ids := object.get(f, "transform_call_ast_ids", [])
  count(t_ids) == 0
  t_names := object.get(f, "transform_call_names", [])
  count(t_names) == 0
}

# Allowed (safe) context: presence of a known neutralizer transformation.
allowed_context(f) if {
  t_names := object.get(f, "transform_call_names", [])
  some name in t_names
  name == "sanitize"
}

allowed_context(f) if {
  t_names := object.get(f, "transform_call_names", [])
  some name in t_names
  name == "replace"
}

allowed_context(f) if {
  t_names := object.get(f, "transform_call_names", [])
  some name in t_names
  name == "replaceAll"
}

allowed_context(f) if {
  t_names := object.get(f, "transform_call_names", [])
  some name in t_names
  name == "trim"
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
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