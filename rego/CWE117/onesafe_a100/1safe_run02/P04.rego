package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

driver_key := "cwe117_facts"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals  := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(vals) > 0
  count(kinds) == count(vals)
  some i
  kind := kinds[i]
  val  := vals[i]
  kind == "call_result"
  val == "getenv"
}

neutralization_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "sanitize"
}
neutralization_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replaceAll"
}
neutralization_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "trim"
}

allowed_context(f) if {
  neutralization_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line
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
    "sink":        sink
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line
  ])
}