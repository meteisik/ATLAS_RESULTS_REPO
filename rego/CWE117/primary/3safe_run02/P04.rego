package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detects log messages that include runtime-provided data without CR/LF neutralization."

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

driver_facts := [f | f := data.drivers.cwe117_facts.facts[_]]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  vals := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(vals) > 0
  count(kinds) == count(vals)
  some i
  i < count(kinds)
  kind := kinds[i]
  val := vals[i]
  kind != ""
  val != ""
}

all_origin_literal(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

neutralizing_transform_present(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) > 0
  some n in names
  n == "replaceAll"
}
neutralizing_transform_present(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) > 0
  some n in names
  n == "trim"
}
neutralizing_transform_present(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) > 0
  some n in names
  n == "replace"
}
neutralizing_transform_present(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) > 0
  some n in names
  n == "encode"
}
neutralizing_transform_present(f) if {
  names := object.get(f, "transform_call_names", [])
  count(names) > 0
  some n in names
  n == "escape"
}

allowed_context(f) if {
  all_origin_literal(f)
}
allowed_context(f) if {
  neutralizing_transform_present(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := severity
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
    "policy_id": policy_id,
    "title": title,
    "severity": sev,
    "description": desc,
    "file": file,
    "class": cls,
    "method": method,
    "line": line,
    "fact_type": ftype,
    "sink": sink,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}