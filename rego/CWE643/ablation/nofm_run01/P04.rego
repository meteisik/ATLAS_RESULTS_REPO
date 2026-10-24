package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy layer can detect expressions built from externally controlled input."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f | f := data.drivers.cwe643_facts.facts[_]]

array_contains(arr, val) if {
  some x in arr
  x == val
}

core_positive_condition(f) if {
  object.get(f, "sink_member", "") == "evaluate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "javax.xml.xpath.XPath"
  array_contains(object.get(f, "origin_kinds", []), "call_result")
}

safe_all_literals(f) if {
  every kind in object.get(f, "origin_kinds", []) { kind == "literal" }
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_all_literals(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

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
    v.policy_id,
    v.title,
    file,
    line,
  ])
}