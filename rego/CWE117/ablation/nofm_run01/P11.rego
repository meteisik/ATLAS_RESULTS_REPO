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

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

#
# Helper: true if any sanitizer is applied
#
has_sanitizer(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "sanitize"
}
has_sanitizer(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "sanitizeCRLF"
}
has_sanitizer(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "sanitizeLFCR"
}

#
# Helper: true if all origins are literals
#
all_literal(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds { k == "literal" }
}

#
# Core positive condition: a runtime call_result reaches the log without neutralization
#
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k == "call_result"
  not has_sanitizer(f)
}

#
# Safe contexts: all literals or sanitized
#
allowed_context(f) if {
  has_sanitizer(f)
}
allowed_context(f) if {
  all_literal(f)
}

#
# Policy violation predicate
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# findings: normalize violating facts into a standard structure
#
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

#
# deny: human-readable messages for each finding
#
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}