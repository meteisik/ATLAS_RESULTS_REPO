package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detects logging of externally controlled data without CR/LF neutralization."

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# Guard: origin_kinds contains a runtime-provided value (call_result)
guard_runtime_value(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind == "call_result"
}

# Guard: origin_values contains an external source value (e.g., getenv)
guard_external_value(f) if {
  vals := object.get(f, "origin_values", [])
  some val in vals
  val == "getenv"
}

# Core positive condition: fact_type is log_message_fact and both guards are satisfied
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "log_message_fact"

  guard_runtime_value(f)
  guard_external_value(f)
}

# No allowed contexts for this policy
allowed_context(f) if { false }

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
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

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