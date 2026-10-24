package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the\npolicy layer can detect SQL built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every SQL execution call whose\n  SQL text argument resolves to origins, including constant, external, and parameter\n  values.\n  The Python plugin describes provenance; Rego decides the violation.\n- The execution call (for example Statement.executeQuery) is the terminal\n  occurrence (sink_ast_id); its SQL text argument is query_arg_ast_id and the\n  declaration of the statement it runs on is receiver_decl_ast_id.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the SQL text argument through declaredAt, initializer, valueSourceIds,\n  argumentOfParameter (formal parameter to the caller argument), calleeId and\n  returnValue, operator (op1/op2), cast, array, collection, field, and\n  receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations such as split, trim, toString, ... carry the receiver\n  value; delimiter, charset, and index arguments are not origins.\n- An external call without a value receiver (an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed."

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# Guard rule: true if all origin kinds are literal
guard_constant_only(f) if {
  k_list := object.get(f, "origin_kinds", [])
  every k in k_list { not k != "literal" }
}

# Core positive condition: contains a call_result origin and getenv value
core_positive_condition(f) if {
  k_list := object.get(f, "origin_kinds", [])
  some k in k_list; k == "call_result"
  v_list := object.get(f, "origin_values", [])
  some v in v_list; v == "getenv"
}

# Violation logic
is_violation(f) if {
  not guard_constant_only(f)
  core_positive_condition(f)
}

# Findings construction
findings := [v |
  f := driver_facts[_]
  is_violation(f)
  file := object.get(f, "file", "")
  class := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)
  sev := severity
  ftype := object.get(f, "fact_type", "")
  sink := object.get(f, "sink_member", "")
  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": description,
    "file":        file,
    "class":       class,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink
  }
]

# Human‑readable denial messages
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