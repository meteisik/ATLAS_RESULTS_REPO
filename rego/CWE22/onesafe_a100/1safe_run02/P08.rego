package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the\npolicy layer can detect paths built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every file path construction (for example\n  new java.io.File(path)) whose path argument resolves to origins, including\n  constant, external, and parameter values. The Python plugin describes\n  provenance; Rego decides the violation. \n- The path construction is the terminal occurrence\n  (sink_ast_id); its path argument is path_arg_ast_id. A downstream creation\n  or call that receives the constructed File (for example a FileInputStream)\n  is recorded as file_consumer_ast_id evidence, never as a second occurrence.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the path argument through declaredAt,\n  initializer, valueSourceIds,\n  argumentOfParameter (formal parameter to the caller argument), calleeId and\n  returnValue, operator (op1/op2), cast, array, collection, field, and\n  receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order,\n  including the constant root directory.\n- Receiver transformations carry the receiver value; delimiter, charset, and\n  index arguments are not origins.\n- An external call without a value receiver (an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is a path whose origins include a runtime-provided value: a\n  call_result of an external read, a field without a constant writer, or an\n  unresolved formal parameter, appended without validation.\n- SAFE is a path whose origins are all literal/constant terminals. A\n  constant root combined with runtime data is still runtime-derived.\n- Resolve every constructor/API identity from the graph: creationKind\n  and\n  callKind follow calleeId to the callable envelope and ownerTypeId to the\n  declaring type's qualifiedName. Lexical spellings on the use-site node are\n  not identity evidence.\n\nOUTPUT INVARIANTS:\n- Emit exactly one fact per terminal sink_ast_id, violating AND safe alike.\n- Every nonzero AST id resolves in the loaded AST; absent structure is 0,\n  the empty string, or an empty list, never invented.\n- All names, values, types, locations, and classifications are derived\n  from the loaded facts schema, domain-model tags, and AST."

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

core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "file_path_fact"
  kinds := object.get(f, "origin_kinds", [])
  vals  := object.get(f, "origin_values", [])
  count(kinds) == count(vals)
  count(kinds) > 0
  some idx
  idx < count(kinds)
  kinds[idx] == "call_result"
  vals[idx] == "getenv"
}

guard_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  every kind in kinds { kind == "literal" }
}

guard_no_runtime_values(f) if {
  vals := object.get(f, "origin_values", [])
  every val in vals { not val == "getenv" }
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_literal_only(f)
  not guard_no_runtime_values(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line,
  ])

  finding := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": desc,
    "file":        file_raw,
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