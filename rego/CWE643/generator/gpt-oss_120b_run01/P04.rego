package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy layer can detect expressions built from externally controlled input."

primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Guard: ensure we are looking at an XPath evaluate call
guard_sink_member_is_evaluate(f) if {
  object.get(f, "sink_member", "") == "evaluate"
}

# Guard: ensure the sink node is a method invocation
guard_sink_node_type_is_method_invocation(f) if {
  object.get(f, "sink_node_type", "") == "method_invocation"
}

# Guard: ensure the resolved type is javax.xml.xpath.XPath
guard_sink_resolved_type_is_xpath(f) if {
  object.get(f, "sink_resolved_type", "") == "javax.xml.xpath.XPath"
}

# Core positive condition: at least one non‑literal origin kind and a
# corresponding runtime‑derived value.
core_positive_condition(f) if {
  guard_sink_member_is_evaluate(f)
  guard_sink_node_type_is_method_invocation(f)
  guard_sink_resolved_type_is_xpath(f)

  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])

  some i
  i < count(origin_kinds)
  origin_kinds[i] != "literal"
  origin_values[i] != ""
}

# Safe context: all origins are literals
allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
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

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  ftype  := object.get(f, "fact_type", "")
  sink   := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,

    "file":   file,
    "class":  cls,
    "method": method,
    "line":   line,
    "fact_type": ftype,
    "sink":   sink,
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