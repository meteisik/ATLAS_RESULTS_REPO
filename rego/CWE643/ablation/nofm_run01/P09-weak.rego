package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy\nlayer can detect expressions built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every XPath evaluation call (for example\n  XPath.evaluate) whose expression argument resolves to origins, including\n  constant, external, and parameter values. The Python plugin describes\n  provenance; Rego decides the violation.\n- The evaluation call is the terminal occurrence (sink_ast_id);\n  its\n  expression argument is query_arg_ast_id and the XPath object's declaration\n  is receiver_decl_ast_id. The input source and result-type arguments are\n  not part of the expression.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the expression argument through declaredAt, initializer,\n  valueSourceIds, argumentOfParameter (formal parameter to the caller\n  argument), calleeId and returnValue, operator (op1/op2), cast, array,\n  collection, field, and receiver relationships, across methods and classes\n  of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations such as split, replace, or getBytes carries its receiver value; its delimiter argument and the index of an element read are not origins.\n- An external call without a value receiver (for example an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed.\n- Every string field is copied verbatim from the current graph node envelope or\n  properties bag named by its companion node-id field; absent structure is\n  represented by 0, an empty string, or an empty list.\n- Facts describe structure only; whether an occurrence violates the policy is decided by the Rego layer."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

is_violation(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind != "literal"
}

is_violation(f) if {
  every kind in object.get(f, "origin_kinds", []) { kind == "literal" }
  count(object.get(f, "origin_kinds", [])) < 5
}

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
  }
]

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