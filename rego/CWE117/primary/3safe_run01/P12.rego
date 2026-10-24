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
# Helper: test whether a list is non‑empty
#
non_empty_list(list) := true if {
  is_array(list)
  count(list) > 0
}

#
# Core positive condition: violations have non‑empty origins and no transforms
#
core_positive_condition(f) if {
  origins := object.get(f, "origin_kinds", [])
  non_empty_list(origins)

  values := object.get(f, "origin_values", [])
  non_empty_list(values)

  transforms := object.get(f, "transform_call_names", [])
  is_array(transforms)
  count(transforms) == 0

  transform_ids := object.get(f, "transform_call_ast_ids", [])
  is_array(transform_ids)
  count(transform_ids) == 0
}

#
# Safe guard: origin_kinds empty
#
safe_origin_kinds_empty(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) == 0
}

#
# Safe guard: only literal origins and no transforms
#
safe_literal_only_no_transform(f) if {
  kinds := object.get(f, "origin_kinds", [])
  is_array(kinds)
  count(kinds) > 0
  every kind in kinds { kind == "literal" }

  transforms := object.get(f, "transform_call_names", [])
  is_array(transforms)
  count(transforms) == 0
}

#
# Allowed context: any safe guard satisfied
#
allowed_context(f) if {
  safe_origin_kinds_empty(f)
}
allowed_context(f) if {
  safe_literal_only_no_transform(f)
}

#
# Violation predicate
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings
#
findings := [v |
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

  v := {
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

#
# Human‑readable denial messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}