package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detect file path constructions that incorporate runtime‑derived values, which can lead to path traversal vulnerabilities."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Core violation logic
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# Positive condition: fact must be a file_path_fact and contain a runtime‑derived origin
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "file_path_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])
  count(origin_kinds) > 0
  count(origin_values) > 0

  some i
  origin_kinds[i] == "call_result"
  origin_values[i] != ""
}

# Guard: safe when all origin kinds are literals
guard_safe_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

# Guard: optional declaration metadata is neutral; treat non‑sentinel as safe
guard_optional_declaration_metadata(f) if {
  object.get(f, "path_arg_decl_ast_id", 0) != 0
  object.get(f, "path_arg_decl_name", "") != ""
}

# Allowed (safe) contexts
allowed_context(f) if {
  guard_safe_literal_only(f)
}
allowed_context(f) if {
  guard_optional_declaration_metadata(f)
}

# Findings: normalize violating facts into a standard structure
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

    # Preserve all original fact fields for downstream tooling
    "sink_ast_id":            object.get(f, "sink_ast_id", 0),
    "origin_ast_ids":         object.get(f, "origin_ast_ids", []),
    "origin_kinds":           object.get(f, "origin_kinds", []),
    "origin_values":          object.get(f, "origin_values", []),
    "sink_node_type":         object.get(f, "sink_node_type", ""),
    "sink_member":            object.get(f, "sink_member", ""),
    "sink_resolved_type":     object.get(f, "sink_resolved_type", ""),
    "sink_stmt_ast_id":       object.get(f, "sink_stmt_ast_id", 0),
    "col":                    object.get(f, "col", 0),
    "method_id":              object.get(f, "method_id", 0),
    "path_arg_ast_id":        object.get(f, "path_arg_ast_id", 0),
    "path_arg_decl_ast_id":   object.get(f, "path_arg_decl_ast_id", 0),
    "path_arg_decl_name":     object.get(f, "path_arg_decl_name", ""),
    "file_consumer_ast_id":   object.get(f, "file_consumer_ast_id", 0)
  }
]

# Deny: human‑readable messages for each finding
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}