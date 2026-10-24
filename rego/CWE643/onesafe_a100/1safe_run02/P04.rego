package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy\nlayer can detect expressions built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every XPath evaluation call (for example\n  XPath.evaluate) whose expression argument resolves to origins, including\n  constant, external, and parameter values. The Python plugin describes\n  provenance; Rego decides the violation.\n- The evaluation call is the terminal occurrence (sink_ast_id);\n  its\n  expression argument is query_arg_ast_id and the XPath object's declaration\n  is receiver_decl_ast_id. The input source and result-type arguments are\n  not part of the expression.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the expression argument through declaredAt, initializer,\n  valueSourceIds, argumentOfParameter (formal parameter to the caller\n  argument), calleeId and returnValue, operator (op1/op2), cast, array,\n  collection, field, and receiver relationships, across methods and classes\n  of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations such as split carry the receiver value; the\n  delimiter argument and the index of an element read are not origins.\n- An external call without a value receiver (an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is an expression whose origins include a runtime-provided\n  value: a call_result of an external read, a field without a constant\n  writer, or an unresolved formal parameter, concatenated into the\n  evaluated expression.\n- SAFE is an expression whose origins are all literal/constant terminals.\n  Literal XPath fragments combined with runtime data are still\n  runtime-derived.\n- Resolve every API identity from the graph: callKind follows calleeId to\n  the callable envelope and ownerTypeId to the declaring type's\n  qualifiedName. Lexical spellings on the use-site node are not identity\n  evidence.\n"

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
  f := data.drivers.cwe643_facts.facts[_]
]

# Helper to check if a value string looks like a literal XPath fragment
is_literal_value(v) if {
  v == "null"
}
is_literal_value(v) if {
  indexof(v, "/") != -1
}
is_literal_value(v) if {
  indexof(v, "[") != -1
}
is_literal_value(v) if {
  indexof(v, "]") != -1
}
is_literal_value(v) if {
  indexof(v, "'") != -1
}

has_runtime_origin_kind(f) if {
  ks := object.get(f, "origin_kinds", [])
  some k in ks
  k != "literal"
}

has_runtime_origin_value(f) if {
  vs := object.get(f, "origin_values", [])
  some v in vs
  not is_literal_value(v)
}

core_positive_condition(f) if {
  has_runtime_origin_kind(f)
  has_runtime_origin_value(f)
}

allowed_context(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  every k in ks { k == "literal" }
  every v in vs { is_literal_value(v) }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

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
  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
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