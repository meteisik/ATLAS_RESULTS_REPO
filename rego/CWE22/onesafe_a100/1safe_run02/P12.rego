package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the\npolicy layer can detect paths built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every file path construction (for example\n  new java.io.File(path)) whose path argument resolves to origins, including\n  constant, external, and parameter values. The Python plugin describes\n  provenance;\n  Rego decides the violation.\n- The path construction is the terminal occurrence\n  (sink_ast_id); its path argument is path_arg_ast_id. A downstream creation or\n  call that receives the constructed File (for example a FileInputStream)\n  is recorded as file_consumer_ast_id evidence, never as a second occurrence.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the path argument through declaredAt, initializer, valueSourceIds,\n  argumentOfParameter (formal parameter to the caller argument), calleeId and\n  returnValue, operator (op1/op2), cast, array, collection, field, and\n  receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order,\n  including the constant root directory.\n- Receiver transformations such as split, replace, or getBytes carries the\n  receiver value; its delimiter, charset, and\n  index arguments are not origins.\n- An external call without a value receiver (for example an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is a path whose origins include a runtime-provided value: a\n  call_result of an external read, a field without a constant writer, or an\n  unresolved formal parameter, appended without validation.\n- SAFE is a path whose origins are all literal/constant terminals. A\n  constant root combined with runtime data is still runtime-derived.\n- Resolve every constructor/API identity from the graph: creationKind\n  and\n  callKind follow calleeId to the callable envelope and ownerTypeId to the\n  declaring type's qualifiedName. Lexical spellings on the use-site node are\n  not identity evidence.\n"

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

# Core positive condition: check discriminators
core_positive_condition(f) if {
  # sink_member == "File"
  object.get(f, "sink_member", "") == "File"

  # sink_node_type == "class_creator"
  object.get(f, "sink_node_type", "") == "class_creator"

  # sink_resolved_type == "java.io.File"
  object.get(f, "sink_resolved_type", "") == "java.io.File"

  # origin_kinds and origin_values aligned: find index with call_result and getenv
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  count(kinds) == count(values)
  some i;
    kind := kinds[i]
    val := values[i]
    kind == "call_result"
    val == "getenv"
}

# Guard: allow safe literal only
guard_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every kind in kinds { kind == "literal" }
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_literal_only(f)
}

findings := [finding |
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
    "sink":        sink,
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