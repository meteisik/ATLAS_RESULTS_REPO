package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath expressions built from externally controlled input, which can lead to injection attacks."

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

primary_fact_type := "xpath_query_fact"

core_positive_condition(f) if {
  ok := object.get(f, "origin_kinds", [])
  ov := object.get(f, "origin_values", [])
  count(ok) > 0
  count(ov) == count(ok)
  some val in ok
  val == "call_result"
}

allowed_context(f) if {
  false
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  line   := object.get(f, "line", 0)
  col    := object.get(f, "col", 0)
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "file":        file,
    "line":        line,
    "col":         col,
    "class":       cls,
    "method":      method,
    "fact_type":   ftype,
    "sink":        sink,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  method := object.get(v, "method", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}