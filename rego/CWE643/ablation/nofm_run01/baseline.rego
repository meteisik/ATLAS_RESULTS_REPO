package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy\nlayer can detect expressions built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every XPath evaluation call (for example\n  XPath.evaluate) whose expression argument resolves to origins, including\n  constant, external, and parameter values. The Python plugin describes\n  provenance; Rego decides the violation.\n- The evaluation call is the terminal occurrence (sink_ast_id);\n  its expression argument is query_arg_ast_id and the XPath object's declaration\n  is receiver_decl_ast_id. The input source and result-type arguments are\n  not part of the expression.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the expression argument through declaredAt, initializer,\n  valueSourceIds, argumentOfParameter (formal parameter to the caller\n  argument), calleeId and returnValue, operator (op1/op2), cast, array,\n  collection, field, and receiver relationships, across methods and classes\n  of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations such as split, replace, or getBytes carries its receiver value; its delimiter argument and the index of an element read are not origins.\n- An external call without a value receiver (for example an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed.\n- Every string field is copied verbatim from the current graph node envelope or properties bag named by its companion node-id field; absent structure is represented by 0, an empty string, or an empty list.\n- Facts describe structure only; whether an occurrence violates the policy is decided by the Rego layer."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f | f := data.drivers.cwe643_facts.facts[_]]

# Helper: check if an array contains a value
array_contains(arr, val) if {
  some x in arr
  x == val
}

# Core positive condition: at least one call_result origin kind and a getenv origin value
core_positive_condition(f) if {
  array_contains(object.get(f, "origin_kinds", []), "call_result")
  array_contains(object.get(f, "origin_values", []), "getenv")
}

# Guard: exclude facts whose all origin_kinds are 'literal' and all origin_values are literal fragments
safe_literal_guard(f) if {
  every kind in object.get(f, "origin_kinds", []) { kind == "literal" }
  every val in object.get(f, "origin_values", []) { val != "getenv" }
}

# Violation rule
is_violation(f) if {
  core_positive_condition(f)
  not safe_literal_guard(f)
}

# Findings
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := object.get(f, "severity", severity)
  ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink   := object.get(f, "sink", "")

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
    "sink":        sink,
  }
]

# Deny messages
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}