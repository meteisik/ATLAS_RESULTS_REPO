package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every SQL execution call whose SQL text argument resolves to origins, including constant, external, and parameter values.\n  The Python plugin describes provenance; Rego decides the violation.\n- The execution call (for example Statement.executeQuery) is the terminal occurrence (sink_ast_id); its SQL text argument is query_arg_ast_id and the declaration of the statement it runs on is receiver_decl_ast_id.\n- Discover candidates from the loaded detection contract. Application method, class, parameter, and variable names are copied output only and are never detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the SQL text argument through declaredAt, initializer, valueSourceIds, argumentOfParameter (formal parameter to the caller argument), calleeId and returnValue, operator (op1/op2), cast, array, collection, field, and receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations such as split, trim, toString, ... carry the receiver value; delimiter, charset, and index arguments are not origins.\n- An external call without a value receiver (an environment read) is itself a call_result origin; its arguments are not followed.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is SQL text whose origins include a runtime-provided value: a call_result of an external read, a field without a constant writer, or an unresolved formal parameter, concatenated into the executed text.\n- SAFE is SQL text whose origins are all literal/constant terminals. A literal fragment combined with runtime data is still runtime-derived.\n- Resolve every API identity from the graph: callKind follows calleeId to the callable envelope and ownerTypeId to the declaring type's qualifiedName. Lexical spellings on the use-site node are not identity evidence.\n\nOUTPUT INVARIANTS:\n- Emit exactly one fact per terminal sink_ast_id, violating AND safe alike.\n- Every nonzero AST id resolves in the loaded AST; absent structure is 0, the empty string, or an empty list, never invented.\n- All names, values, types, locations, and classifications are derived from the loaded facts schema, domain-model tags, and AST."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

#
# Core violation logic
#
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_values := object.get(f, "origin_values", [])
  some i
  origin_kinds[i]
  origin_values[i]
  origin_kinds[i] != "literal"
  origin_values[i] != ""
}

allowed_context(f) if {
  false
}

#
# Findings
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
# Human-readable deny messages
#
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}