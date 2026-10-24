package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := "Describe the provenance of the SQL text of every JDBC query execution so the policy layer can detect SQL built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact per JDBC query execution site, violating and safe alike.\n- The execution call is the terminal occurrence (sink_ast_id); its SQL text argument is query_arg_ast_id.\n- Backward value proof: a concatenation retains every outermost operand origin.\n- Receiver transformations carry the receiver value; external calls without a value receiver are call_result origins."

driver_key := "cwe89_facts"
primary_fact_type := "sql_query_fact"

driver_facts := [f | f := data.drivers.cwe89_facts.facts[_]]

core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  k != "literal"
}

core_positive_condition(f) if {
  values := object.get(f, "origin_values", [])
  some v in values
  regex.match("getenv", v)
}

core_positive_condition(f) if {
  query_id := object.get(f, "query_arg_ast_id", 0)
  origins := object.get(f, "origin_ast_ids", [])
  not query_id in origins
  kinds := object.get(f, "origin_kinds", [])
  every k in kinds { k == "literal" }
}

is_violation(f) if {
  core_positive_condition(f)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)
  file_raw := object.get(f, "file", object.get(f, "file_path", ""))
  line := object.get(f, "line", 0)
  span_raw := object.get(f, "span", {"start": {"line": line}})
  fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
  method_name := object.get(f, "method_name", "")
  method_id := object.get(f, "method_id", 0)
  call_ast_id := object.get(f, "sink_ast_id", 0)
  sink := object.get(f, "sink_member", "")
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
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [v.policy_id, v.title, file, line, method])
}