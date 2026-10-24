package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detect log messages that contain runtime‑provided data without CR/LF neutralizing transformations."

primary_fact_type := "log_message_fact"
driver_key := "cwe117_facts"

# canonical fact list
driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# core condition: runtime‑provided origin (call_result) present,
# origin lists non‑empty, and no transformation recorded.
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "log_message_fact"

  oks := object.get(f, "origin_kinds", [])
  is_array(oks)
  count(oks) > 0
  some k in oks
  k == "call_result"

  ovs := object.get(f, "origin_values", [])
  is_array(ovs)
  count(ovs) > 0

  tcn := object.get(f, "transform_call_names", [])
  is_array(tcn)
  count(tcn) == 0
}

# guard: any recorded transformation makes the finding safe
guard_transform_present(f) if {
  tcn := object.get(f, "transform_call_names", [])
  is_array(tcn)
  count(tcn) > 0
}

# violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not guard_transform_present(f)
}

# findings for violating facts
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink_member", ""),
  }
]

# deny messages
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