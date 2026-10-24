package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every logging call (for example Logger.info) whose message argument resolves to origins, including constant, external, and parameter values. The Python plugin describes provenance; Rego decides the violation.\n- The logging call is the terminal occurrence (sink_ast_id); its message argument is message_arg_ast_id and the logger declaration it runs on is receiver_decl_ast_id.\n- Discover candidates from the loaded detection contract. Application method, class, parameter, and variable names are copied output only and are never detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the message argument through declaredAt, initializer, valueSourceIds, argumentOfParameter (formal parameter to the caller argument), calleeId and returnValue, operator (op1/op2), cast, array, collection, field, and receiver relationships, across methods and classes of the analyzed file.\n- A concatenation retains every outermost operand origin in operand order.\n- Receiver transformations (replace, replaceAll, trim, ...) carry the receiver value; their pattern and replacement arguments are not origins.\n- An external call without a value receiver (an environment, property, console, network, or request read) is itself a call_result origin; its arguments are not followed.\n- transform_call_ast_ids / transform_call_names record every same-graph method call whose return value, and every receiver transformation whose receiver, the proof passes through, between the origins and the sink, including calls inside called helpers. They are empty when the value reaches the log call unchanged.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is a message whose origins include a runtime-provided value (a call_result of an external read, a field without a constant writer, or an unresolved formal parameter) that reaches the log call without passing a CR/LF-neutralizing transformation.\n- SAFE is a message whose origins are all literal/constant terminals, or whose runtime-provided value passes a neutralizing transformation first: a sanitizer method or receiver transformations that remove or encode carriage-return and line-feed characters, recorded in transform_call_names.\n- Resolve every API identity from the graph: callKind follows calleeId to the callable envelope and ownerTypeId to the declaring type's qualifiedName. Lexical spellings on the use-site node are not identity evidence.\n\nOUTPUT INVARIANTS:\n- Emit exactly one fact per terminal sink_ast_id, violating AND safe alike.\n- Every nonzero AST id resolves in the loaded AST; absent structure is 0, the empty string, or an empty list, never invented.\n- All names, values, types, locations, and classifications are derived from the loaded facts schema, domain-model tags, and AST.\n"

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# Core violation logic
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  kinds := object.get(f,"origin_kinds",[])
  values := object.get(f,"origin_values",[])
  names := object.get(f,"transform_call_names",[])
  some i
  i < count(kinds)
  kind := kinds[i]
  kind == "call_result"
  val := values[i]
  val != ""
  count(names) == 0
}

allowed_context(f) if false

findings := [finding |
  f := driver_facts[_]
  is_violation(f)
  file   := object.get(f,"file",object.get(f,"file_path",""))
  cls    := object.get(f,"class_name","")
  method := object.get(f,"method_name","")
  line   := object.get(f,"line",0)
  sev    := object.get(f,"severity",severity)
  ftype  := object.get(f,"fact_type",object.get(f,"kind",""))
  sink   := object.get(f,"sink","")
  desc := sprintf("Policy %s violation at %s.%s (line %v)", [
    policy_id, cls, method, line
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
  file := object.get(v,"file","")
  line := object.get(v,"line",0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line
  ])
}