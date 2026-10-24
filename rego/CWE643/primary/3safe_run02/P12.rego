package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detect XPath expressions built from externally controlled input."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

#
# Core violation logic
#
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(values) > 0
  count(kinds) == count(values)
  some idx
  idx < count(kinds)
  kind := kinds[idx]
  kind == "call_result"
  val := values[idx]
  val == "getenv"
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every kind in kinds { kind == "literal" }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings: emit one for each fact, marking whether it is a violation.
#
findings := [v |
  f := driver_facts[_]
  file := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")
  violation := is_violation(f)
  v := {
    "policy_id": policy_id,
    "title": title,
    "severity": sev,
    "description": description,
    "file": file,
    "class": cls,
    "method": method,
    "line": line,
    "fact_type": ftype,
    "sink": sink,
    "violation": violation
  }
]

#
# Human-readable messages for violations only.
#
deny contains msg if {
  v := findings[_]
  violation := v.violation
  violation
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