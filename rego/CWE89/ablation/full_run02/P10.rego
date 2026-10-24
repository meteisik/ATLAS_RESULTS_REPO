package policies.cwe89
import rego.v1

policy_id := "CWE89"
title := "SQL Injection"
severity := "CRITICAL"
description := `Describe the provenance of the SQL text of every JDBC query execution so the
policy layer can detect SQL built from externally controlled input.

NEUTRAL FACT BOUNDARY:
- Emit one neutral fact for every SQL execution call whose SQL text argument
  resolves to origins, including constant, external, and parameter values.
  The Python plugin describes provenance; Rego decides the violation.
- The execution call (for example Statement.executeQuery) is the terminal
  occurrence (sink_ast_id); its SQL text argument is query_arg_ast_id and the
  declaration of the statement it runs on is receiver_decl_ast_id.
- Discover candidates from the loaded detection contract. Application method,
  class, parameter, and variable names are copied output only and are never
  detection gates.

BACKWARD VALUE PROOF:
- Trace the SQL text argument through declaredAt, initializer, valueSourceIds,
  argumentOfParameter (formal parameter to the caller argument), calleeId and
  returnValue, operator (op1/op2), cast, array, collection, field, and
  receiver relationships, across methods and classes of the analyzed file.
- A concatenation retains every outermost operand origin in operand order.
- Receiver transformations such as split, trim, toString, ... carry the receiver
  value; delimiter, charset, and index arguments are not origins.
- An external call without a value receiver (an environment, property,
  console, network, or request read) is itself a call_result origin; its
  arguments are not followed.

SOURCE SEMANTICS (recorded as structure, decided by Rego):
- A VIOLATION is SQL text whose origins include a runtime-provided value: a
  call_result of an external read, a field without a constant writer,
  or an unresolved formal parameter, concatenated into the executed text.
- SAFE is SQL text whose origins are all literal/constant terminals. A
  literal fragment combined with runtime data is still runtime-derived.
- Resolve every API identity from the graph: callKind follows calleeId to
  the callable envelope and ownerTypeId to the declaring type's
  qualifiedName. Lexical spellings on the use-site node are not identity
  evidence.`

driver_facts := [f |
  f := data.drivers.cwe89_facts.facts[_]
]

# Core violation logic
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

core_positive_condition(f) if {
  values := object.get(f, "origin_values", [])
  some val in values
  val == "getenv"
}

allowed_context(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  every kind in kinds { kind == "literal" }
  every val in values { val != "getenv" }
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)

  sink_member := object.get(f, "sink_member", "")
  sink_member == "executeQuery"

  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"

  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "java.sql.Statement"

  sink_ast_id := object.get(f, "sink_ast_id", 0)
  sink_ast_id != 0
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
  sink := object.get(f, "sink_member", "")

  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id,
    cls,
    method,
    line,
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