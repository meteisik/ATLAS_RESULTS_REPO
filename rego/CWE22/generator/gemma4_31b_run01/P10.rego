package policies.cwe22
import rego.v1

# Basic metadata for this policy.
policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file-system paths constructed from externally controlled runtime values."

# Driver key this policy consumes facts from.
driver_key := "cwe22_facts"

# Primary fact_type this policy cares about.
primary_fact_type := "file_path_fact"

#
# Canonical fact list for this policy
#
driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

#
# Core violation logic
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Hook 1: the core "this looks bad" condition.
# A violation is triggered if the path construction involves runtime-derived sources
# (e.g., 'call_result', 'parameter', 'field') and the origins are non-sentinel.
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  
  # Unanimous discriminators must be non-sentinel
  count(kinds) > 0
  count(vals) > 0
  
  # Trigger if any origin is not a literal (i.e., it is runtime-derived)
  some k in kinds
  k != "literal"
}

# Hook 2: safe/allowed contexts to subtract out false positives.
# SAFE is a path whose origins are all literal/constant terminals.
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  
  # Exclude paths composed entirely of constants/literals
  every k in kinds { k == "literal" }
}

#
# findings: normalize violating facts into a standard structure
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  # Robust field extraction using object.get.
  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v): Path constructed from runtime-provided values.", [
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