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

core_positive_condition(f) if {
  some kind in f.origin_kinds
  kind != "literal"
}

safe_xpath_guard(f) if {
  every kind in f.origin_kinds {
    kind == "literal"
  }
}

is_violation(f) if {
  core_positive_condition(f)
  not safe_xpath_guard(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)
  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)
  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", "")
  sink := object.get(f, "sink_member", "")
  desc := sprintf("Policy %s violation at %s.%s (line %v)", [policy_id, cls, method, line])
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
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}