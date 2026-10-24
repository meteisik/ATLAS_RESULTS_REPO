package policies.cwe643
import rego.v1

# Policy metadata
policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath expressions constructed from externally controlled input. Each XPath evaluation site emits a fact; this policy flags expressions whose provenance includes runtime input."

# Fact source
driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Guard: ensure the fact represents a call to XPath.evaluate
safe_xpath_evaluate_invocation(f) if {
  object.get(f, "sink_member", "") == "evaluate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "javax.xml.xpath.XPath"
}

# Helper: check for any non‑literal kind in origin_kinds
contains_non_literal_kind(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind != "literal"
}

# Helper: check for a runtime value in origin_values
contains_runtime_value(f) if {
  some val in object.get(f, "origin_values", [])
  val == "getenv"
}

# Core positive condition: guarded by safe XPath evaluate invocation
core_positive_condition(f) if {
  safe_xpath_evaluate_invocation(f)
  contains_non_literal_kind(f)
  contains_runtime_value(f)
}

# Allowed context: none for this policy
allowed_context(f) if {
  false
}

# Violation rule
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Findings
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink_member", "")

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

# Human‑readable deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}