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

# Ensure all required fields are present in the fact.
required_fields_present(f) if {
  object.get(f, "origin_kinds", null) != null
  object.get(f, "origin_values", null) != null
  object.get(f, "transform_call_names", null) != null
}

# Core positive condition for a violation:
#   - at least one origin_kinds entry is 'call_result'
#   - no neutralizing transformation has been applied
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k == "call_result"
  names := object.get(f, "transform_call_names", [])
  count(names) == 0
}

# Guard rules that allow safe logs
allowed_context(f) if allow_literal_only(f)
allowed_context(f) if allow_neutralized(f)

# Safe logs where all origins are literals
allow_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

# Safe logs that have undergone a neutralising transformation
allow_neutralized(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  neutralizing(n)
}

neutralizing(n) if { n == "replace" }
neutralizing(n) if { n == "replaceAll" }
neutralizing(n) if { n == "trim" }

# A fact is a violation if it meets the core condition and is not in an allowed context,
# or if it is missing any required field.
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}
is_violation(f) if {
  not required_fields_present(f)
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