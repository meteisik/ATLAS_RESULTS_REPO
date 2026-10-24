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

guard_all_literal_origins(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds { k == "literal" }
}

guard_non_literal_origin_present(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}

core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  ks != []
  vs != []
}

is_violation(f) if {
  core_positive_condition(f)
  guard_non_literal_origin_present(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink", ""),
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