package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(values) > 0
}

origin_has_call_result(f) if {
  some k in object.get(f, "origin_kinds", [])
  k == "call_result"
}

origin_has_getenv(f) if {
  some v in object.get(f, "origin_values", [])
  contains(v, "getenv")
}

allow_sanitize_transformation(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "sanitize"
  origin_has_call_result(f)
}
allow_sanitize_transformation(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "sanitize"
  origin_has_getenv(f)
}

allow_replace_transformations(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replace"
  origin_has_call_result(f)
}
allow_replace_transformations(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replace"
  origin_has_getenv(f)
}

allow_replaceAll_transformations(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replaceAll"
  origin_has_call_result(f)
}
allow_replaceAll_transformations(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replaceAll"
  origin_has_getenv(f)
}

allowed_context(f) if { allow_sanitize_transformation(f) }
allowed_context(f) if { allow_replace_transformations(f) }
allowed_context(f) if { allow_replaceAll_transformations(f) }

violation_call_result(f) if {
  core_positive_condition(f)
  origin_has_call_result(f)
}

violation_getenv(f) if {
  core_positive_condition(f)
  origin_has_getenv(f)
}

is_violation(f) if {
  violation_call_result(f)
  not allowed_context(f)
}
is_violation(f) if {
  violation_getenv(f)
  not allowed_context(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})
  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name := object.get(f, "method_name", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "call_ast_id", 0)
  sink := object.get(f, "sink", "")

  v := {
    "policy_id": policy_id,
    "title": title,
    "severity": severity,
    "description": description,
    "file": file_raw,
    "span": span_raw,
    "fact_type": fact_type_val,
    "method_name": method_name,
    "method_id": method_id,
    "call_ast_id": call_ast_id,
    "sink": sink,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  span := object.get(v, "span", {})
  start := object.get(span, "start", {})
  line := object.get(start, "line", 0)
  method := object.get(v, "method_name", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}