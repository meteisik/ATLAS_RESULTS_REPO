package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "XPath expression built from externally controlled input: a runtime-provided value is concatenated into the evaluated XPath expression."

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0

  some k in kinds
  k != "literal"

  values := object.get(f, "origin_values", [])
  is_array(values)
  count(values) > 0
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every k in kinds {
    k == "literal"
  }
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

  desc := sprintf("XPath injection: runtime-provided value in evaluated XPath expression at %s.%s (line %v)", [
    cls, method, line,
  ])

  finding := {
    "policy_id":          policy_id,
    "title":              title,
    "severity":           severity,
    "description":        desc,

    "class":              cls,
    "method":             method,
    "line":               line,
    "col":                col,

    "fact_type":          "xpath_query_fact",
    "sink_ast_id":        object.get(f, "sink_ast_id", 0),
    "sink_member":        object.get(f, "sink_member", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
  }
]

deny contains msg if {
  v := findings[_]

  cls  := object.get(v, "class", "")
  meth := object.get(v, "method", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s.%s (line %d)", [
    v.policy_id, v.title, cls, meth, line,
  ])
}