package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f | f := data.drivers.cwe22_facts.facts[_]]

SAFE_ROOT := "/home/user/uploads/"

allow_literal_only_paths(f) if {
  every kind in f.origin_kinds { kind == "literal" }
  every val in f.origin_values { val == SAFE_ROOT }
  f.path_arg_decl_ast_id == 0
  count(f.origin_ast_ids) == 1
  f.path_arg_ast_id == f.origin_ast_ids[0]
}

allowed_context(f) if {
  allow_literal_only_paths(f)
}

core_positive_condition(f) if {
  some i; kind := f.origin_kinds[i]; kind != "literal"
}
core_positive_condition(f) if {
  some i; val := f.origin_values[i]; val != SAFE_ROOT
}
core_positive_condition(f) if {
  f.path_arg_ast_id != f.origin_ast_ids[0]
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", "")
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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}