package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_key := "cwe22_facts"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Guard: path construction must be a java.io.File constructor
guard_file_constructor(f) if {
  object.get(f, "sink_member", "") == "File"
  object.get(f, "sink_node_type", "") == "class_creator"
  object.get(f, "sink_resolved_type", "") == "java.io.File"
}

# Guard: all origins must be literal
guard_literal_only(f) if {
  ks := object.get(f, "origin_kinds", [])
  ks == ["literal"]
}

# Allowed context: safe when both guards are satisfied
allowed_context(f) if {
  guard_file_constructor(f)
  guard_literal_only(f)
}

# Core positive condition: only file constructor facts are considered
core_positive_condition(f) if {
  guard_file_constructor(f)
}

# Violation predicate
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink_member", "")

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