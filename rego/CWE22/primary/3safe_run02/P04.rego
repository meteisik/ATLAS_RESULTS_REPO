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

# Helper to fetch a list field with a default
getlist(o, k) := l if {
  l := object.get(o, k, [])
}

#
# Core positive condition: any origin_kinds value that is not "literal"
#
core_positive_condition(f) if {
  kinds := getlist(f, "origin_kinds")
  some k in kinds
  k != "literal"
}

#
# Safe context (never matches, all facts are considered violations unless allowed_context is explicitly defined)
#
allowed_context(f) if {
  false
}

#
# is_violation: a fact is a violation if it matches the core positive condition
# and is not in an allowed context
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# findings: normalize violating facts into a standard structure
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    severity,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   object.get(f, "fact_type", ""),
    "sink":        object.get(f, "sink_member", ""),
    "class_name":   object.get(f, "class_name", ""),
    "col":          object.get(f, "col", 0),
    "file_consumer_ast_id": object.get(f, "file_consumer_ast_id", 0),
    "method_id":   object.get(f, "method_id", 0),
    "origin_ast_ids": object.get(f, "origin_ast_ids", []),
    "origin_kinds":  object.get(f, "origin_kinds", []),
    "origin_values": object.get(f, "origin_values", []),
    "path_arg_ast_id": object.get(f, "path_arg_ast_id", 0),
    "path_arg_decl_ast_id": object.get(f, "path_arg_decl_ast_id", 0),
    "path_arg_decl_name": object.get(f, "path_arg_decl_name", ""),
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
    "sink_member": object.get(f, "sink_member", ""),
    "sink_node_type": object.get(f, "sink_node_type", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
    "sink_stmt_ast_id": object.get(f, "sink_stmt_ast_id", 0)
  }
]

#
# deny: human-readable messages for each finding
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [policy_id, title, file, line])
}