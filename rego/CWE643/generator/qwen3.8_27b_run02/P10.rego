package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath expressions built from externally controlled input where a runtime-provided value is concatenated into the evaluated XPath query."

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  is_array(origin_kinds)
  count(origin_kinds) > 0
  some kind in origin_kinds
  kind != "literal"

  origin_values := object.get(f, "origin_values", [])
  is_array(origin_values)
  count(origin_values) > 0
}

allowed_context(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  is_array(origin_kinds)
  count(origin_kinds) > 0
  every kind in origin_kinds {
    kind == "literal"
  }
}

allowed_context(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  not is_array(origin_kinds)
}

allowed_context(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  is_array(origin_kinds)
  count(origin_kinds) == 0
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  col    := object.get(f, "col", 0)
  sink   := object.get(f, "sink_member", "")
  sink_type := object.get(f, "sink_resolved_type", "")

  desc := sprintf("XPath expression at %s.%s (line %v) is built from externally controlled input", [
    cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,

    "class_name":         cls,
    "method_name":        method,
    "line":               line,
    "col":                col,
    "sink_member":        sink,
    "sink_resolved_type": sink_type,
    "sink_ast_id":        object.get(f, "sink_ast_id", 0),
    "fact_type":          object.get(f, "fact_type", "xpath_query_fact"),
  }
]

deny contains msg if {
  v := findings[_]

  cls    := object.get(v, "class_name", "")
  method := object.get(v, "method_name", "")
  line   := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s.%s (line %d)", [
    v.policy_id, v.title, cls, method, line,
  ])
}