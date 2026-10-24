package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detect file path constructions that include runtime-provided values."

# Driver key this policy consumes facts from.
driver_key := "cwe22_facts"

# Optional: primary fact_type this policy cares about (metadata only).
primary_fact_type := "file_path_fact"

#
# Canonical fact list for this policy
#
driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

#
# Core violation logic: a path is violating if any origin kind is
# "call_result" and the corresponding origin value is non-empty
#
core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  count(ks) > 0
  count(vs) > 0
  some i
  i < count(ks)
  i < count(vs)
  ks[i] == "call_result"
  vs[i] != ""
}

#
# A fact is a violation when it satisfies the core positive condition.
#
is_violation(f) if {
  core_positive_condition(f)
}

#
# findings: normalize violating facts into a standard structure
#
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink_ast_id", 0)

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
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