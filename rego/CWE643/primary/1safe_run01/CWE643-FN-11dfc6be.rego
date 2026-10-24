package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy layer can detect expressions built from externally controlled input."

#
# Facts produced by the driver for this policy.
#
driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

#
# Small boolean-field helper:
#
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

#
# Extract the fact_type (or kind) if present.
fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

#
# Core violation logic
#
# A fact is a violation if either:
#   * one of its origin_kinds is not "literal"
#   * or one of its origin_values is a known runtime‑derived value
#     such as "getenv" or "RUNE_HELIX_ADD".
#
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

core_positive_condition(f) if {
  vals := object.get(f, "origin_values", [])
  some val in vals
  val == "getenv"
}

core_positive_condition(f) if {
  vals := object.get(f, "origin_values", [])
  some val in vals
  val == "RUNE_HELIX_ADD"
}

#
# A fact is a violation if it satisfies the core condition.
#
is_violation(f) if {
  core_positive_condition(f)
}

#
# findings: normalize driver_facts that are violations into a standard
# structure consumed by the validator and by downstream tools.
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line     := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})

  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name   := object.get(f, "method_name", "")
  method_id     := object.get(f, "method_id", 0)
  call_ast_id   := object.get(f, "call_ast_id", 0)

  sink := object.get(f, "sink", "")

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,

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
# deny: human-readable messages for each finding
#
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