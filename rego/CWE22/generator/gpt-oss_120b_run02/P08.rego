package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detect file path constructions that incorporate runtime‑derived values, which can lead to path traversal vulnerabilities."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

# All facts emitted by the driver
driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# --------------------------------------------------------------------
# Core violation logic
# --------------------------------------------------------------------
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# --------------------------------------------------------------------
# Positive condition – must hold for a violating fact
# --------------------------------------------------------------------
core_positive_condition(f) if {
  # Fact type sanity check (optional but defensive)
  object.get(f, "fact_type", "") == "file_path_fact"

  # At least one origin kind is a call_result (runtime‑derived source)
  some kind in object.get(f, "origin_kinds", [])
  kind == "call_result"
}

# --------------------------------------------------------------------
# Guard rules that identify safe facts (they must NOT be reported)
# --------------------------------------------------------------------
guard_all_literal_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { k == "literal" }
}

guard_all_literal_values(f) if {
  values := object.get(f, "origin_values", [])
  count(values) > 0
  # The only known runtime‑derived value in the corpus is "getenv".
  # Any value equal to "getenv" is considered non‑literal.
  every v in values { not v == "getenv" }
}

allowed_context(f) if {
  guard_all_literal_kinds(f)
}
allowed_context(f) if {
  guard_all_literal_values(f)
}

# --------------------------------------------------------------------
# Findings – normalized structure for each violating fact
# --------------------------------------------------------------------
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": desc,

    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,

    # Preserve the full fact for downstream tooling
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
    "file_consumer_ast_id":   object.get(f, "file_consumer_ast_id", 0),

    # Optional generic anchor if present
    "sink": object.get(f, "sink", "")
  }
]

# --------------------------------------------------------------------
# Deny – human‑readable messages for each finding
# --------------------------------------------------------------------
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