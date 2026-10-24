package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy layer can detect expressions built from externally controlled input."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  count(ks) == count(vs)
  count(ks) > 0
  some i
  ks[i] == "call_result"
  vs[i] == "getenv"
  m := object.get(f, "sink_member", "")
  m == "evaluate"
  sn := object.get(f, "sink_node_type", "")
  sn == "method_invocation"
  sr := object.get(f, "sink_resolved_type", "")
  sr == "javax.xml.xpath.XPath"
}

non_literal_found(f) if {
  ks := object.get(f, "origin_kinds", [])
  some i
  ks[i] != "literal"
}

guard_literal_only(f) if {
  ks := object.get(f, "origin_kinds", [])
  count(ks) > 0
  not non_literal_found(f)
}

allowed_context(f) if {
  guard_literal_only(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
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