package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

#
# Driver key this policy consumes facts from.
#
driver_key := "cwe117_facts"

#
# Canonical fact list for this policy
#
driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

#
# Core violation logic
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# The core "this looks bad" condition.
#
core_positive_condition(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind != "literal"

  count(object.get(f, "transform_call_names", [])) == 0
}

#
# Safe contexts to subtract out false positives.
#
allowed_context(f) if {
  false
}

#
# findings: normalize driver_facts that are violations into a standard structure
#
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