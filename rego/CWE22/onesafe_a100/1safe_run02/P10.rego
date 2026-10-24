package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  is_array(kinds)
  is_array(vals)
  count(kinds) > 0
  count(vals) > 0
}

guard_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every kind in kinds { kind == "literal" }
}

guard_no_runtime_values(f) if {
  vals := object.get(f, "origin_values", [])
  every val in vals { val != "getenv" }
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_literal_only(f)
  not guard_no_runtime_values(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  ftype := object.get(f, "fact_type", "")
  sink := object.get(f, "sink_member", "")

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,

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