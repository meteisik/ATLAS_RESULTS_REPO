package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it\npasses through, so the policy layer can detect externally controlled data\nwritten to a log without CR/LF neutralization.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every logging call (for example Logger.info)\n  whose message argument resolves to origins, including constant, external,\n  and parameter values. The Python plugin describes provenance; Rego decides\n  the violation.\n- The logging call is the terminal occurrence (sink_ast_id); its message\n  argument is message_arg_ast_id and the logger declaration it runs on is\n  receiver_decl_ast_id.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the message argument through declaredAt, initializer, valueSourceIds,\n  argumentOfParameter (formal parameter to the caller argument), calleeId and\n  returnValue, operator (op1/op2), cast, array, collection, field, and\n  receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations (replace, replaceAll, trim, ...) carry the\n  receiver value; their pattern and replacement arguments are not origins.\n- An external call without a value receiver (an environment, property,\n  console, network, or request read) is itself a call_result origin; its\n  arguments are not followed.\n- transform_call_ast_ids / transform_call_names record every same-graph\n  method call whose return value, and every receiver transformation whose\n  receiver, the backward value proof passes through, between the origins and the sink,\n  including calls inside called helpers. They are empty when the value\n  reaches the log call unchanged.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is a message whose origins include a runtime-provided value\n  (a call_result of an external read, a field without a constant writer, or\n  an unresolved formal parameter) that reaches the log call without passing\n  a CR/LF-neutralizing transformation.\n- SAFE is a message whose origins are all literal/constant terminals, or\n  whose runtime-provided value passes a neutralizing transformation first:\n  a sanitizer method or receiver transformations that remove or encode\n  carriage-return and line-feed characters, recorded in\n  transform_call_names.\n- Resolve every API identity from the graph: callKind follows calleeId to\n  the callable envelope and ownerTypeId to the declaring type's\n  qualifiedName. Lexical spellings on the use-site node are not identity\n  evidence.\n\nOUTPUT INVARIANTS:\n- Emit exactly one fact per terminal sink_ast_id, violating AND safe alike.\n- Every nonzero AST id resolves in the loaded AST; absent structure is 0,\n  the empty string, or an empty list, never invented.\n- All names, values, types, locations, and classifications are derived\n  from the loaded facts schema, domain-model tags, and AST."

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# Set of known CR/LF neutralizing transformation names
sanitizer_name := "replaceAll" if { true }
sanitizer_name := "trim" if { true }
sanitizer_name := "sanitizeCRLF" if { true }

# Guard: safe if all origins are literals
safe_literal_only(f) if {
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds { not k != "literal" }
}

# Guard: safe if any neutralizing transformation is present
safe_neutralized(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "replaceAll"
}
safe_neutralized(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "trim"
}
safe_neutralized(f) if {
  names := object.get(f, "transform_call_names", [])
  some n in names
  n == "sanitizeCRLF"
}

# Core positive condition: requires a call_result origin with a non‑empty value
# and no neutralizing transformations
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  count(kinds) == count(values)
  some i
  kind := kinds[i]
  kind == "call_result"
  val := values[i]
  val != ""
  names := object.get(f, "transform_call_names", [])
  count(names) == 0
}

# A fact is a violation only if it satisfies the core condition and
# does not fall under either safe guard
is_violation(f) if {
  core_positive_condition(f)
  not safe_literal_only(f)
  not safe_neutralized(f)
}

findings := [finding |
  f := driver_facts[_]
  violation := is_violation(f)

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
    "description": description,
    "file":        file,
    "class":       cls,
    "method":      method,
    "line":        line,
    "fact_type":   ftype,
    "sink":        sink,
    "is_violation": violation,
  }
]

deny contains msg if {
  v := findings[_]
  v.is_violation
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id,
    v.title,
    file,
    line,
  ])
}