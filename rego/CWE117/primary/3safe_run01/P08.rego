package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

driver_facts := [f | f := data.drivers.cwe117_facts.facts[_] ]

# Helper to safely retrieve a list field
getlist(f, key) := lst if {
  lst := object.get(f, key, [])
  is_array(lst)
}

# Core positive condition: a log message that contains a runtime origin and no neutralizing transformation
core_positive_condition(f) if {
  t := object.get(f, "fact_type", "")
  t == "log_message_fact"

  origins := getlist(f, "origin_kinds")
  values  := getlist(f, "origin_values")
  transforms := getlist(f, "transform_call_names")

  # Require at least one call_result origin
  some v in origins
    v == "call_result"

  # Require at least one non-empty origin value (covers runtime value)
  some val in values
    val != ""

  # Require no neutralizing transformations
  count(transforms) == 0
}

# Guard: logs whose origins are all literals (no runtime data)
log_only_literals(f) if {
  origins := getlist(f, "origin_kinds")
  every v in origins { v == "literal" }
}

# Guard: logs that have undergone a neutralizing transformation
log_sanitized_transformation(f) if {
  transforms := getlist(f, "transform_call_names")
  count(transforms) > 0
}

# A fact is allowed (safe) if it satisfies any guard
allowed_context(f) if { log_only_literals(f) }
allowed_context(f) if { log_sanitized_transformation(f) }

# A fact is a violation if it meets the core condition and is not allowed
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings: structured representation of violations
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

  desc   := sprintf("Policy %s violation at %s.%s (line %v)", [policy_id, cls, method, line])

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
    "sink":        sink
  }
]

# Human‑readable denial messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}