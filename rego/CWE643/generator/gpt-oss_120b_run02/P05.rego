package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy layer can detect expressions built from externally controlled input."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

# Canonical fact list
driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Core violation detection
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Positive condition: presence of a non‑literal origin (e.g., call_result)
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "xpath_query_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  some k in origin_kinds
  k != "literal"
}

# Guard: all origins are literals → safe
guard_all_literal_kinds(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every k in origin_kinds {
    k == "literal"
  }
}

# Guard: all origin values are compile‑time constants (no external reads like getenv)
guard_all_constant_values(f) if {
  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
  every v in origin_values {
    v != "getenv"
  }
}

# Guard: sink metadata matches the uniform pattern observed in violations
guard_constant_sink_metadata(f) if {
  object.get(f, "sink_member", "") == "evaluate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "javax.xml.xpath.XPath"
}

# Allowed (safe) context: sink metadata matches AND either of the other guards holds
allowed_context(f) if {
  guard_constant_sink_metadata(f)
  guard_all_literal_kinds(f)
}
allowed_context(f) if {
  guard_constant_sink_metadata(f)
  guard_all_constant_values(f)
}

# Findings construction
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))

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
  }
]

# Human‑readable deny messages
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id,
    v.title,
    file,
    line,
  ])
}