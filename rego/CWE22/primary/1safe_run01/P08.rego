package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

#
# Facts produced by the driver for this policy.
#
driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

#
# Helper to check if a fact contains a call_result origin.
#
has_call_result(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind == "call_result"
}

#
# Core violation logic: a fact is a violation if it contains a call_result origin
# and the sink_ast_id is non‑zero.
#
is_violation(f) if {
  has_call_result(f)
  object.get(f, "sink_ast_id", 0) != 0
}

#
# findings: normalize violating facts into a standard structure
#
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink          := object.get(f, "sink", "")
  sink_ast_id   := object.get(f, "sink_ast_id", 0)
  sink_member   := object.get(f, "sink_member", "")
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   fact_type_val,
    "sink":        sink,
    "sink_ast_id": sink_ast_id,
    "sink_member": sink_member,
    "sink_node_type": sink_node_type,
    "sink_resolved_type": sink_resolved_type,
    "classification": "VIOLATION",
  }
]

#
# deny: human-readable messages for each finding
#
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