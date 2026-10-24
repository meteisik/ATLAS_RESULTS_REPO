package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file-system paths constructed from externally controlled runtime values."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  # Enforce required sink identity discriminators
  object.get(f, "sink_member", "") == "File"
  object.get(f, "sink_node_type", "") == "class_creator"
  object.get(f, "sink_resolved_type", "") == "java.io.File"

  # Ensure provenance lists are present and non-sentinel
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  vals := object.get(f, "origin_values", [])
  count(vals) > 0

  # Violation is triggered by the presence of at least one runtime-derived origin
  # (e.g., 'call_result', 'parameter', 'field', 'unknown')
  some k in kinds
  k != "literal"
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0

  # SAFE is a path whose origins are all literal/constant terminals
  every k in kinds { k == "literal" }
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

  desc := sprintf("Policy %s violation at %s.%s (line %v): Path constructed from externally controlled runtime values.", [
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

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}