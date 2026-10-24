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

#
# Core violation logic
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  kind_list := object.get(f, "origin_kinds", null)
  kind_list != null
  count(kind_list) > 0
  val_list := object.get(f, "origin_values", null)
  val_list != null
  count(val_list) > 0
  names := object.get(f, "transform_call_names", null)
  names != null
  count(names) == 0
}

#
# Guard rules
#
safe_if_call_result_neutralized(f) if {
  kind_list := object.get(f, "origin_kinds", [])
  some k in kind_list
  k == "call_result"
  names := object.get(f, "transform_call_names", [])
  count(names) > 0
}

safe_if_all_literal(f) if {
  kind_list := object.get(f, "origin_kinds", [])
  kind_list != null
  every k in kind_list { k == "literal" }
}

allowed_context(f) if { safe_if_call_result_neutralized(f) }
allowed_context(f) if { safe_if_all_literal(f) }

#
# Findings
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)
  col := object.get(f, "col", 0)
  span_raw := object.get(f, "span", {"start": {"line": line, "col": col}})

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name := object.get(f, "method_name", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "call_ast_id", object.get(f, "sink_ast_id", 0))
  sink := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id,
    cls,
    method,
    line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,
    "file":        file_raw,
    "span":        span_raw,
    "fact_type":   fact_type_val,
    "method_name": method_name,
    "method_id":   method_id,
    "call_ast_id": call_ast_id,
    "sink":        sink,
  }
]

#
# Deny messages
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