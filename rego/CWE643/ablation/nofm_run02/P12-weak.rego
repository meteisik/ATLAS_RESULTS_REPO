package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath queries built from runtime values such as environment variables."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f | f := data.drivers.cwe643_facts.facts[_]]

runtime_origin_present(f) if {
  some i
  kinds := object.get(f, "origin_kinds", [])
  kinds[i] == "unknown"
}

runtime_origin_present(f) if {
  some i
  kinds := object.get(f, "origin_kinds", [])
  kinds[i] == "call_result"
}

runtime_origin_present(f) if {
  some i
  kinds := object.get(f, "origin_kinds", [])
  kinds[i] == "parameter"
}

contains_quote_or_slash(s) if {
  contains(s, "\"")
}
contains_quote_or_slash(s) if {
  contains(s, "'")
}
contains_quote_or_slash(s) if {
  contains(s, "/")
}

runtime_value_present(f) if {
  some i
  vals := object.get(f, "origin_values", [])
  val := vals[i]
  val != ""
  val != "null"
  not contains_quote_or_slash(val)
}

core_positive_condition(f) if {
  runtime_origin_present(f)
  runtime_value_present(f)
}

allowed_context(f) if {
  every kind in object.get(f, "origin_kinds", []) { kind == "literal" }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
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