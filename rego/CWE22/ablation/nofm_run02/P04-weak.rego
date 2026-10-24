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

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  some k in origin_kinds
  k == "call_result"
}

core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) == 1
  k := origin_kinds[0]
  k == "literal"
  path_arg_decl_ast_id := object.get(f, "path_arg_decl_ast_id", 0)
  path_arg_decl_ast_id == 0
  origin_values := object.get(f, "origin_values", [])
  count(origin_values) == 1
  v := origin_values[0]
  endswith(v, "/")
}

allowed_context(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  every k in origin_kinds { k == "literal" }
  origin_values := object.get(f, "origin_values", [])
  count(origin_values) == 1
  v := origin_values[0]
  not endswith(v, "/")
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
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