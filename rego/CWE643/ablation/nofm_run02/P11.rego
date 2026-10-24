package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath queries built from runtime values such as environment variables."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

contains_non_literal_kind(f) if {
  some k in object.get(f, "origin_kinds", [])
  k != "literal"
}

contains_literal_chars(v) if {
  contains(v, "/")
}
contains_literal_chars(v) if {
  contains(v, "=")
}
contains_literal_chars(v) if {
  contains(v, "[")
}
contains_literal_chars(v) if {
  contains(v, "]")
}
contains_literal_chars(v) if {
  contains(v, "'")
}
contains_literal_chars(v) if {
  contains(v, ".")
}

contains_non_constant_value(f) if {
  some v in object.get(f, "origin_values", [])
  not contains_literal_chars(v)
}

core_positive_condition(f) if {
  contains_non_literal_kind(f)
  contains_non_constant_value(f)
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