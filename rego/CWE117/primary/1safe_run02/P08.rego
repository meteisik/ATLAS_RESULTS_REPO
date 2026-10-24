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

# Small boolean-field helper
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

# Core positive condition: origins and values present, and no neutralizer
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0

  values := object.get(f, "origin_values", [])
  count(values) > 0

  not allow_if_neutralizer_present(f)
}

# Guard: neutralizing transformations
allow_if_neutralizer_present(f) if {
  names := object.get(f, "transform_call_names", [])
  some name in names
  name == "replace"
}
allow_if_neutralizer_present(f) if {
  names := object.get(f, "transform_call_names", [])
  some name in names
  name == "replaceAll"
}
allow_if_neutralizer_present(f) if {
  names := object.get(f, "transform_call_names", [])
  some name in names
  name == "trim"
}
allow_if_neutralizer_present(f) if {
  names := object.get(f, "transform_call_names", [])
  some name in names
  name == "escape"
}
allow_if_neutralizer_present(f) if {
  names := object.get(f, "transform_call_names", [])
  some name in names
  name == "sanitize"
}

is_violation(f) if {
  core_positive_condition(f)
}

findings := [v |
  f := driver_facts[_]
  violation := is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
    "is_violation": violation,
  }
]

deny contains msg if {
  v := findings[_]
  v.is_violation
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id,
    v.title,
    file,
    line,
  ])
}