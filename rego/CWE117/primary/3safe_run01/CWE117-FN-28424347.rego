package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

#
# Canonical fact list for this policy
#
driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

#
# Helper: check if a list contains a specific value
#
contains_value(list, val) if {
  some v in list
  v == val
}

#
# Neutralizing transformation names
#
neutralizing := {"replace": true, "replaceAll": true, "trim": true}

#
# Helper: check if a list contains any neutralizing transformation
#
neutralizing_present(list) if {
  some t in list
  object.get(neutralizing, t, false)
}

#
# Acceptable transform_call_names: empty or containing a neutralizing transformation
#
neutralizing_or_empty(f) if {
  transforms := object.get(f, "transform_call_names", [])
  neutralizing_present(transforms)
}

neutralizing_or_empty(f) if {
  transforms := object.get(f, "transform_call_names", [])
  count(transforms) == 0
}

#
# Core positive condition: call_result origin present and transform condition satisfied
#
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  contains_value(kinds, "call_result")
  neutralizing_or_empty(f)
}

#
# Guard: neutralization applied
#
neutralization_applied(f) if {
  transforms := object.get(f, "transform_call_names", [])
  neutralizing_present(transforms)
}

#
# Guard: safe literal only (all origins literal and no transforms)
#
safe_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds {
    k == "literal"
  }
  transforms := object.get(f, "transform_call_names", [])
  count(transforms) == 0
}

#
# Violation logic
#
is_violation(f) if {
  core_positive_condition(f)
  not neutralization_applied(f)
}

#
# Findings
#
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line
  ])

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
    "sink":        sink,
  }
]

#
# Human-readable deny messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}