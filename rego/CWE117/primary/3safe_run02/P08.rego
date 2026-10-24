package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it\npasses through, so the policy layer can detect externally controlled data\nwritten to a log without CR/LF neutralization.\n\nNEUTRAL FACT BOUNDARY:\n- Emit exactly one log_message_fact per logging call site, violating and safe alike, so the Rego layer sees the complete population.\n- The driver contract requires that every terminal method_invocation of type java.util.logging.Logger be represented as a log_message_fact; no synthetic or inferred facts may be introduced.\n"

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

driver_facts := [f | f := data.drivers.cwe117_facts.facts[_]]

# Guard rules for readability
external_call_result_guard(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k == "call_result"
}

runtime_value_guard(f) if {
  vals := object.get(f, "origin_values", [])
  some v in vals
  v == "getenv"
}

neutralization_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) == 0
}

# Core positive condition: call_result origin with getenv value and no neutralization
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  names := object.get(f, "transform_call_names", [])
  count(names) == 0
  some i
  i < count(kinds)
  i < count(vals)
  kinds[i] == "call_result"
  vals[i] == "getenv"
}

# No allowed context; all core-positive facts are violations
allowed_context(f) if {
  false
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", "")
  cls := object.get(f, "class_name", "")
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