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
  kinds := object.get(f, "origin_kinds", [])
  
  count(kinds) > 0
  
  # A violation is characterized by the presence of a runtime-provided value.
  # According to the committed plan and policy spec, any origin that is not a 'literal'
  # (e.g., 'call_result', 'parameter', 'field') constitutes a runtime-derived source.
  some k in kinds
  k != "literal"
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  
  # SAFE is a path whose origins are all literal/constant terminals.
  every k in kinds { k == "literal" }
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  # Extract fields based on the provided FACTS_DESIGN_JSON and ACTUAL_EMITTED_FACTS.
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

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}