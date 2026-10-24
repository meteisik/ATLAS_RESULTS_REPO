package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the\npolicy layer can detect paths built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every file path construction (for example\n  new java.io.File(path)) whose path argument resolves to origins, including\n  constant, external, and parameter values. The Python plugin describes\n  provenance; Rego decides the violation.\n- The path construction is the terminal occurrence\n  (sink_ast_id); its path argument is path_arg_ast_id. A downstream creation or call that receives the constructed File as an argument, directly or through the local declaration holding it; 0 when none.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the path argument through declaredAt, initializer, valueSourceIds,\n  argumentOfParameter (formal parameter to the caller argument), calleeId and\n  returnValue, operator (op1/op2), cast, array, collection, field, and\n  receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order,\n  including the constant root directory.\n- Receiver transformations such as split, replace, or getBytes carries its receiver value; its delimiter, charset, and\n  index arguments are not origins. A external call without a value receiver\n  (for example an environment read) is itself a call_result origin; its\n  arguments are not followed.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is a path whose origins include a runtime-provided value: a\n  call_result of an external read, a field without a constant writer, or an\n  unresolved formal parameter, appended without validation.\n- SAFE is a path whose origins are all literal/constant terminals. A\n  constant root combined with runtime data is still runtime-derived.\n\nOUTPUT INVARIANTS:\n- Emit exactly one fact per terminal sink regardless of safety, but only\n  classify it as SAFE when the guard passes.\n- Every nonzero AST id resolves in the analyzed AST; absent structure is 0, the empty string, or an empty list, never invented.\n- All names, values, types, locations, and classifications are derived\n  from the loaded facts schema, domain-model tags, and AST."

primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

#
# Core violation logic
#
core_positive_condition(f) if {
  some kind in f.origin_kinds
  kind == "call_result"
}
core_positive_condition(f) if {
  some val in f.origin_values
  val == "getenv"
}

#
# Guard rules to allow only safe paths
#
guard_literal_only_paths(f) if {
  every kind in f.origin_kinds { kind == "literal" }
}
guard_constant_values(f) if {
  every val in f.origin_values { val != "getenv" }
}
allowed_context(f) if {
  guard_literal_only_paths(f)
  guard_constant_values(f)
}

#
# Violation predicate
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

#
# Findings: normalize violating facts into a standard structure
#
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

#
# Human‑readable messages for each finding
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}