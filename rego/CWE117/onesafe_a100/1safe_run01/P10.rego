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

# Guard: exclude logs whose all origin_kinds are literal (no runtime data)
guard_no_runtime_origin(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { not k != "literal" }
}

# Guard: exclude logs whose transform_call_names contains a CR/LF neutralizer
guard_neutralized_runtime(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names; n == "replace"
}
guard_neutralized_runtime(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names; n == "replaceAll"
}
guard_neutralized_runtime(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names; n == "trim"
}

# Core positive condition: fact type and presence of origin data
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "log_message_fact"
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  vals := object.get(f, "origin_values", [])
  count(vals) > 0
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_no_runtime_origin(f)
  not guard_neutralized_runtime(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id,
    cls,
    method,
    line,
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
    v.policy_id,
    v.title,
    file,
    line,
  ])
}