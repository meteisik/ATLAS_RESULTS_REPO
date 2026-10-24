package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detect file path constructions that include runtime-provided values."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Guard: sink identity must match expected constants
guard_sink_identity(f) if {
  sm := object.get(f, "sink_member", "")
  sm == "File"
  sn := object.get(f, "sink_node_type", "")
  sn == "class_creator"
  sr := object.get(f, "sink_resolved_type", "")
  sr == "java.io.File"
}

# Guard: origin_kinds must include a non‑literal kind
guard_non_literal_origin_kinds(f) if {
  ks := object.get(f, "origin_kinds", [])
  some k in ks
  k != "literal"
}

# Guard: origin_values must contain a runtime‑derived string (no slash)
guard_runtime_origin_values(f) if {
  vs := object.get(f, "origin_values", [])
  some v in vs
  v != ""
  not contains(v, "/")
}

# Core positive condition: all guards satisfied
core_positive_condition(f) if {
  guard_sink_identity(f)
  guard_non_literal_origin_kinds(f)
  guard_runtime_origin_values(f)
}

is_violation(f) if {
  core_positive_condition(f)
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
  sink   := object.get(f, "sink_ast_id", 0)

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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}