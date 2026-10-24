package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detect file path constructions that incorporate runtime‑derived values, which can lead to path‑traversal vulnerabilities."

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Core positive condition: fact is of type file_path_fact,
# origin_kinds is non‑empty and contains at least one non‑literal kind,
# and origin_values is non‑empty.
core_positive_condition(f) if {
  ft := object.get(f, "fact_type", "")
  ft == "file_path_fact"

  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0

  some i
  i < count(kinds)
  kind := kinds[i]
  kind != "literal"

  values := object.get(f, "origin_values", [])
  count(values) > 0
}

# Guard: all origins are literals (safe).
guard_literal_only_origin_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

# Guard: no provenance information recorded (treated as safe).
guard_no_origins(f) if {
  count(object.get(f, "origin_kinds", [])) == 0
}

allowed_context(f) if {
  guard_literal_only_origin_kinds(f)
}
allowed_context(f) if {
  guard_no_origins(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [v |
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
    "sink":        object.get(f, "sink", ""),

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

deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}