package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every SQL execution call whose\n  SQL text argument resolves to origins, including constant, external, and parameter\n  values.\n  The Python plugin describes provenance; Rego decides the violation.\n- The execution call (for example Statement.executeQuery) is the terminal\n  occurrence (sink_ast_id); its SQL text argument is query_arg_ast_id and the\n  declaration of the statement it runs on is receiver_decl_ast_id.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the SQL text argument through declaredAt, initializer, valueSourceIds,\n  argumentOfParameter (formal parameter to the caller argument), calleeId and\n  returnValue, operator (op1/op2), cast, array, collection, field, and\n  receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations such as split, trim, toString, ... carry the receiver\n  value; delimiter, charset, and index arguments are not origins.\n- An external call without a value receiver (an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# Helper to check if any non-literal kind present
non_literal_kind_present(f) if {
  k_list := object.get(f, "origin_kinds", [])
  some k in k_list; k != "literal"
}

# Helper to check if any runtime value present
runtime_value_present(f) if {
  v_list := object.get(f, "origin_values", [])
  count(v_list) > 0
}

core_positive_condition(f) if {
  non_literal_kind_present(f)
  runtime_value_present(f)
}

# No allowlist: all contexts are allowed
allowed_context(f) if {
  false
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls  := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := severity
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink_member", "")

  finding := {
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
  method := object.get(v, "method", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method
  ])
}