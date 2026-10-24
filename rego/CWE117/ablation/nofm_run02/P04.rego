package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

driver_key := "cwe117_facts"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# Helper: check if a fact contains a call_result origin with a runtime value
has_call_result_origin(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals  := object.get(f, "origin_values", [])
  count(kinds) == count(vals)
  count(kinds) > 0
  some i
  i < count(kinds)
  kind := kinds[i]
  val  := vals[i]
  kind == "call_result"
  val != ""
}

# Guard: the message passes through a known CR/LF neutralizer
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "trim"
}
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replaceAll"
}
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replace"
}
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "sanitize"
}
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "escape"
}
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "encode"
}
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "clean"
}
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "strip"
}
neutralizer_guard(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "removeCRLF"
}

# Core positive condition: a call_result origin with a runtime value, and the sink is a Logger.info call
core_positive_condition(f) if {
  has_call_result_origin(f)

  member := object.get(f, "sink_member", "")
  member == "info"

  node := object.get(f, "sink_node_type", "")
  node == "method_invocation"

  typ := object.get(f, "sink_resolved_type", "")
  typ == "java.util.logging.Logger"
}

is_violation(f) if {
  core_positive_condition(f)
  not neutralizer_guard(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

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