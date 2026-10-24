package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy layer can detect expressions built from externally controlled input."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Core condition: at least one non‑literal origin (e.g., call_result)
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "xpath_query_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  some k in origin_kinds
  k != "literal"
}

# Guard: all origins are literal (safe)
guard_all_literal_origins(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every k in origin_kinds {
    k == "literal"
  }
}

# Guard: sink metadata alone should not trigger a finding
guard_sink_metadata_only(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every k in origin_kinds {
    k == "literal"
  }

  sink_member := object.get(f, "sink_member", "")
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")

  sink_member != "" 
  sink_node_type != "" 
  sink_resolved_type != ""
}

allowed_context(f) if {
  guard_all_literal_origins(f)
}
allowed_context(f) if {
  guard_sink_metadata_only(f)
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