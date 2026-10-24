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

# Helper: get list safely
get_list(o, k) := l if {
  l := object.get(o, k, [])
  is_array(l)
}

# Violation detection: any origin kind that is not "literal"
is_violation(f) if {
  kinds := get_list(f, "origin_kinds")
  count(kinds) > 0
  some k in kinds
  k != "literal"
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", "")
  line := object.get(f, "line", 0)
  cls  := object.get(f, "class_name", "")
  meth := object.get(f, "method_name", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,

    "file":        file,
    "line":        line,
    "class":       cls,
    "method":      meth,

    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink", ""),
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [policy_id, title, file, line])
}