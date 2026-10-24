package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every SQL execution call whose SQL text argument resolves to origins, including constant, external, and parameter values.\n  The Python plugin describes provenance; Rego decides the violation.\n- The execution call (for example Statement.executeQuery) is the terminal occurrence (sink_ast_id); its SQL text argument is query_arg_ast_id and the declaration of the statement it runs on is receiver_decl_ast_id.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the SQL text argument through declaredAt, initializer, valueSourceIds,\n  argumentOfParameter (formal parameter to the caller argument), calleeId and\n  returnValue, operator (op1/op2), cast, array, collection, field, and\n  receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations such as split, trim, toString, ... carry the receiver\n  value; delimiter, charset, and index arguments are not origins.\n- An external call without a value receiver (for example an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

#
# Helper: guard that ensures all origins are literals.
#
guard_safe_literal_sql(f) if {
  k_list := object.get(f, "origin_kinds", [])
  # All kinds must be "literal"
  every k in k_list { not k != "literal" }
}

#
# Core positive condition: any non‑literal origin kind indicates a potential violation.
#
core_positive_condition(f) if {
  k_list := object.get(f, "origin_kinds", [])
  some k in k_list; k != "literal"
}

#
# Violation logic: fact is a violation when core positive condition holds and
# the guard fails (i.e., not all origins are literals).  Also ensure the fact
# has a valid sink_ast_id.
#
is_violation(f) if {
  core_positive_condition(f)
  not guard_safe_literal_sql(f)
  sink_id := object.get(f, "sink_ast_id", 0)
  sink_id != 0
}

#
# findings: normalize driver_facts that are violations into a standard structure
#
findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", "")
  cls := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line := object.get(f, "line", 0)

  sev := severity
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink_member", "")

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

#
# deny: human-readable messages for each finding
#
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
    method,
  ])
}