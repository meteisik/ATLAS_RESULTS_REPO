package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detect file path constructions that incorporate runtime‑controlled input, indicating a potential path‑traversal vulnerability."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Core condition: the fact must be a file_path_fact, refer to java.io.File construction,
# and contain non‑sentinel origin information.
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "file_path_fact"

  sink_member := object.get(f, "sink_member", "")
  sink_member == "File"

  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "class_creator"

  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0

  origin_values := object.get(f, "origin_values", [])
  count(origin_values) > 0
}

# Safe contexts (allowed_context):
# 1) Not a java.io.File construction.
allowed_context(f) if {
  sink_member := object.get(f, "sink_member", "")
  sink_member != "File"
}
allowed_context(f) if {
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type != "class_creator"
}
# 2) All origins are literals (no runtime‑derived values).
allowed_context(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  every k in origin_kinds { k == "literal" }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

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
    v.policy_id,
    v.title,
    file,
    line,
  ])
}