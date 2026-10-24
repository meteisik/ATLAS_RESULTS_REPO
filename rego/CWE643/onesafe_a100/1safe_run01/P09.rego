package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath expressions built from externally controlled input."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Helper: check all kinds are literal
all_literal_kinds(kinds) if {
  every kind in kinds { kind == "literal" }
}

# Helper: check all values are not the runtime call "getenv"
all_literal_vals(vals) if {
  every val in vals { val != "getenv" }
}

# Safe classification: all origins are literal
safe_all_literal(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  all_literal_kinds(kinds)
  all_literal_vals(vals)
}

# Core violation condition
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(vals) > 0
  some i
  i < count(kinds)
  i < count(vals)
  kind := kinds[i]
  val := vals[i]
  kind != "literal"
  val == "getenv"
  sink_member := object.get(f, "sink_member", "")
  sink_member == "evaluate"
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "javax.xml.xpath.XPath"
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_all_literal(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

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
  method := object.get(v, "method", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}