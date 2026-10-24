package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detect XPath expressions that include runtime‑derived input, which can lead to injection vulnerabilities."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Guard: expression is fully literal (safe)
guard_safe_all_literal(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  count(origin_kinds) > 0
  every k in origin_kinds { k == "literal" }
}

allowed_context(f) if {
  guard_safe_all_literal(f)
}

# Core positive condition: presence of a non‑literal kind with a runtime‑derived value
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "xpath_query_fact"

  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])
  count(origin_kinds) > 0
  count(origin_values) > 0

  some i
  i < count(origin_kinds)
  k := origin_kinds[i]
  v := origin_values[i]

  k != "literal"
  not contains(v, "/")
  not contains(v, "'")
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
    "col":         object.get(f, "col", 0),

    "fact_type":   ftype,
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
    "sink_member": object.get(f, "sink_member", ""),
    "sink_node_type": object.get(f, "sink_node_type", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
    "sink_stmt_ast_id": object.get(f, "sink_stmt_ast_id", 0),

    "origin_ast_ids": object.get(f, "origin_ast_ids", []),
    "origin_kinds":   object.get(f, "origin_kinds", []),
    "origin_values":  object.get(f, "origin_values", []),

    "query_arg_ast_id":       object.get(f, "query_arg_ast_id", 0),
    "query_arg_decl_ast_id":  object.get(f, "query_arg_decl_ast_id", 0),
    "query_arg_decl_name":    object.get(f, "query_arg_decl_name", ""),
    "receiver_decl_ast_id":   object.get(f, "receiver_decl_ast_id", 0),
    "receiver_decl_name":     object.get(f, "receiver_decl_name", ""),

    "method_id":   object.get(f, "method_id", 0),
    "method_name": object.get(f, "method_name", ""),
    "class_name":  cls,
  }
]

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