package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy\nlayer can detect expressions built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every XPath evaluation call (for example\n  XPath.evaluate) whose expression argument resolves to origins, including\n  constant, external, and parameter values. The Python plugin describes\n  provenance; Rego decides the violation.\n- The evaluation call is the terminal occurrence (sink_ast_id);\n  its\n  expression argument is query_arg_ast_id and the XPath object's declaration\n  is receiver_decl_ast_id. The input source and result-type arguments are\n  not part of the expression.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the expression argument through declaredAt, initializer,\n  valueSourceIds, argumentOfParameter (formal parameter to the caller\n  argument), calleeId and returnValue, operator (op1/op2), cast, array,\n  collection, field, and receiver relationships, across methods and classes\n  of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations such as split carry the receiver value; the\n  delimiter argument and the index of an element read are not origins.\n- An external call without a value receiver (for example an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed.\n\nSOURCE SEMANTICS (recorded as structure,\ndecided by Rego):\n- A VIOLATION is an expression whose origins include a runtime-provided\n  value: a call_result of an external read, a field without a constant\n  writer, or an unresolved formal parameter, concatenated into the\n  evaluated expression.\n- SAFE is an expression whose origins are all literal/constant terminals.\n  Literal XPath fragments combined with runtime data are still\n  runtime-derived.\n- Resolve every API identity from the graph: callKind follows calleeId to\n  the callable envelope and ownerTypeId to the declaring type's\n  qualifiedName. Lexical spellings on the use-site node are not identity\n  evidence.\n\nOUTPUT INVARIANTS:\n- Emit exactly one fact per terminal sink_ast_id, violating AND safe alike.\n- Every nonzero AST id resolves in the loaded AST; absent structure is 0,\n  the empty string, or an empty list, never invented.\n- All names, values, types, locations, and classifications are derived\n  from the loaded facts schema, domain-model tags, and AST."

driver_facts := [f | f := data.drivers.cwe643_facts.facts[_]]

# Small boolean-field helper
getbool(o, k) := v if { v := object.get(o, k, false); v == true }

# Extract the fact_type (or kind) if present.
fact_type(f) := t if { t := object.get(f, "fact_type", object.get(f, "kind", "")) }

# Core violation logic
core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  count(ks) > 0
  vs := object.get(f, "origin_values", [])
  count(vs) > 0
  object.get(f, "sink_member", "") == "evaluate"
  object.get(f, "sink_node_type", "") == "method_invocation"
  object.get(f, "sink_resolved_type", "") == "javax.xml.xpath.XPath"
}

# Violation determination
is_violation(f) if {
  core_positive_condition(f)
}

# Findings: normalize driver_facts that are violations into a standard structure
findings := [v |
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

  v := {
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

    # Provenance fields
    "origin_ast_ids":        object.get(f, "origin_ast_ids", []),
    "origin_kinds":          object.get(f, "origin_kinds", []),
    "origin_values":         object.get(f, "origin_values", []),
    "query_arg_ast_id":      object.get(f, "query_arg_ast_id", 0),
    "query_arg_decl_ast_id": object.get(f, "query_arg_decl_ast_id", 0),
    "query_arg_decl_name":   object.get(f, "query_arg_decl_name", ""),
    "receiver_decl_ast_id":  object.get(f, "receiver_decl_ast_id", 0),
    "receiver_decl_name":    object.get(f, "receiver_decl_name", ""),
    "sink_ast_id":           object.get(f, "sink_ast_id", 0),
    "sink_node_type":        object.get(f, "sink_node_type", ""),
    "sink_resolved_type":    object.get(f, "sink_resolved_type", ""),
    "sink_stmt_ast_id":      object.get(f, "sink_stmt_ast_id", 0),
  }
]

# Human-readable messages for each finding
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