package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f | f := data.drivers.cwe22_facts.facts[_]]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

runtime_value(v) if {
  v != ""
  not startswith(v, "/")
}

core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  count(ks) > 0
  count(vs) > 0
  count(ks) == count(vs)
  some i
  i < count(ks)
  kind := ks[i]
  kind == "call_result"
}

core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  count(ks) > 0
  count(vs) > 0
  count(ks) == count(vs)
  some i
  i < count(ks)
  val := vs[i]
  runtime_value(val)
}

guard_literal_only(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  count(ks) == 1
  count(vs) == 1
  ks[0] == "literal"
  every val in vs { not runtime_value(val) }
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_literal_only(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}