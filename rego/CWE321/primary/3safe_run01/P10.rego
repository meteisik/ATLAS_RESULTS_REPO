package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key‑material provenance so the policy layer can detect hard‑coded effective keys."

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not guard_runtime_origin(f)
}

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0

  values := object.get(f, "origin_values", [])
  count(values) > 0

  sink_member := object.get(f, "sink_member", "")
  sink_member == "newInstance"

  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"

  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "javax.crypto.spec.SecretKeySpec"
}

guard_runtime_origin(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k == "parameter"
}
guard_runtime_origin(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k == "field"
}
guard_runtime_origin(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k == "config"
}
guard_runtime_origin(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k == "generated"
}
guard_runtime_origin(f) if {
  values := object.get(f, "origin_values", [])
  count(values) == 0
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := severity
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line])

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
    v.policy_id, v.title, file, line])
}