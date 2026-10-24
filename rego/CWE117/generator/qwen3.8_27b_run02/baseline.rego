package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detects externally controlled data written to a log without CR/LF neutralization."

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

core_positive_condition(f) if {
  okinds := object.get(f, "origin_kinds", [])
  is_array(okinds)
  count(okinds) > 0
  some k in okinds
  k != "literal"

  ovals := object.get(f, "origin_values", [])
  is_array(ovals)
  count(ovals) > 0

  tnames := object.get(f, "transform_call_names", [])
  is_array(tnames)
  count(tnames) == 0
}

allowed_context(f) if {
  tnames := object.get(f, "transform_call_names", [])
  is_array(tnames)
  count(tnames) > 0
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
  col    := object.get(f, "col", 0)
  sink   := object.get(f, "sink_member", "")
  ftype  := object.get(f, "fact_type", "log_message_fact")
  sink_id := object.get(f, "sink_ast_id", 0)

  desc := sprintf("Externally controlled value written to %s log without CR/LF neutralization at %s.%s (line %v)", [
    sink, cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "col":         col,
    "fact_type":   ftype,
    "sink":        sink,
    "sink_ast_id": sink_id,
  }
]

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  cls  := object.get(v, "class", "")
  method := object.get(v, "method", "")

  msg := sprintf("[%s] %s at %s:%d (class=%s, method=%s)", [
    v.policy_id, v.title, file, line, cls, method,
  ])
}