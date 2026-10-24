package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath expressions built from externally controlled input."

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

core_positive_condition(f) if {
  o_kinds := object.get(f, "origin_kinds", [])
  o_vals := object.get(f, "origin_values", [])
  count(o_kinds) > 0
  count(o_vals) > 0
  count(o_kinds) == count(o_vals)
  some idx
  kind := o_kinds[idx]
  val := o_vals[idx]
  kind != "literal"
  val == "getenv"
  object.get(f, "sink_member", "") == "evaluate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "javax.xml.xpath.XPath"
}

is_violation(f) if {
  core_positive_condition(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)
  finding := {
    "policy_id": policy_id,
    "title": title,
    "severity": severity,
    "description": description,
    "classification": "VIOLATION",
    "class_name": object.get(f, "class_name", ""),
    "col": object.get(f, "col", 0),
    "fact_type": object.get(f, "fact_type", ""),
    "line": object.get(f, "line", 0),
    "method_id": object.get(f, "method_id", 0),
    "method_name": object.get(f, "method_name", ""),
    "origin_ast_ids": object.get(f, "origin_ast_ids", []),
    "origin_kinds": object.get(f, "origin_kinds", []),
    "origin_values": object.get(f, "origin_values", []),
    "query_arg_ast_id": object.get(f, "query_arg_ast_id", 0),
    "query_arg_decl_ast_id": object.get(f, "query_arg_decl_ast_id", 0),
    "query_arg_decl_name": object.get(f, "query_arg_decl_name", ""),
    "receiver_decl_ast_id": object.get(f, "receiver_decl_ast_id", 0),
    "receiver_decl_name": object.get(f, "receiver_decl_name", ""),
    "sink_ast_id": object.get(f, "sink_ast_id", 0),
    "sink_member": object.get(f, "sink_member", ""),
    "sink_node_type": object.get(f, "sink_node_type", ""),
    "sink_resolved_type": object.get(f, "sink_resolved_type", ""),
    "sink_stmt_ast_id": object.get(f, "sink_stmt_ast_id", 0)
  }
]

deny contains msg if {
  v := findings[_]
  line := object.get(v, "line", 0)
  method := object.get(v, "method_name", "")
  msg := sprintf("[%s] %s at line %v (method=%s)", [
    policy_id,
    title,
    line,
    method,
  ])
}