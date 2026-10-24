package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the policy layer can detect paths built from externally controlled input."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Core positive condition: the fact contains a runtime‑derived origin.
core_positive_condition(f) if {
    ft := object.get(f, "fact_type", "")
    ft == primary_fact_type
    kinds := object.get(f, "origin_kinds", [])
    some k in kinds
    k == "call_result"
}

# Guard: all origin kinds are literal.
guard_literal_only_origin_kinds(f) if {
    kinds := object.get(f, "origin_kinds", [])
    every k in kinds { k == "literal" }
}

# Guard: all origin values are literals (conservative – always true when no call_result).
guard_all_literal_origin_values(f) if {
    # In the current schema, the presence of a "call_result" kind already indicates a non‑literal value.
    # Therefore, if there is no "call_result", we consider all values literal.
    not core_positive_condition(f)
}

# Guard: optional declaration fields are sentinel values.
guard_optional_fields_sentinel(f) if {
    object.get(f, "path_arg_decl_ast_id", 0) == 0
    object.get(f, "path_arg_decl_name", "") == ""
}

# A fact is in an allowed (safe) context when all guard rules hold.
allowed_context(f) if {
    guard_literal_only_origin_kinds(f)
    guard_all_literal_origin_values(f)
    guard_optional_fields_sentinel(f)
}

# Violation predicate.
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

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))

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
    "sink":        object.get(f, "sink", ""),
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