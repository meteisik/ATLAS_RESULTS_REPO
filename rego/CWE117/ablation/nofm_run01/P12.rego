package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  is_array(kinds)
  is_array(values)
  count(kinds) > 0
  count(values) > 0
}

allowed_context(f) if {
  names := object.get(f, "transform_call_names", [])
  is_array(names)
  count(names) > 0
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", "")
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sink_ast_id := object.get(f, "sink_ast_id", 0)
  sink_member := object.get(f, "sink_member", "")
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_resolved_type := object.get(f, "sink_resolved_type", "")

  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])
  transform_call_names := object.get(f, "transform_call_names", [])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "sink_ast_id": sink_ast_id,
    "sink_member": sink_member,
    "sink_node_type": sink_node_type,
    "sink_resolved_type": sink_resolved_type,
    "origin_kinds": origin_kinds,
    "origin_values": origin_values,
    "transform_call_names": transform_call_names,
    "classification": "VIOLATION"
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  classification := object.get(v, "classification", "")
  msg := sprintf("[%s] %s at %s:%d (%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    classification,
  ])
}