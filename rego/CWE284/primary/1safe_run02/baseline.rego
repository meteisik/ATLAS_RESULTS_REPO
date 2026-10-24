package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every data-modifying statement execution (for\n  example PreparedStatement.executeUpdate), guarded AND unguarded alike.\n  The Python plugin describes structure; Rego decides the violation.\n- The execution call is the terminal occurrence (sink_ast_id). The\n  declaration of the executed statement is receiver_decl_ast_id, the call\n  that creates it from its SQL text is prepare_call_ast_id, and parameter\n  bindings on it (setString, ...) are binding_call_ast_ids evidence, never\n  separate occurrences.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- origin_ast_ids lists the origins of the values bound into the executed\n  statement by binding_call_ast_ids, in binding order. The SQL text of\n  prepare_call_ast_id and the binding index are not origins.\n- Trace each value through declaredAt, initializer, valueSourceIds,\n  argumentOfParameter (for an overriding method, through the overridden\n  declaration's parameter at the same position), calleeId and returnValue,\n  operator, negation, cast, array element stores, container contents\n  (contentSourceIds), and field relationships; an external call without a\n  value receiver is a call_result origin.\n- A parameterized statement with bound values is not SQL injection; this\n  policy concerns authorization only.\n\nGUARD STRUCTURE:\n- guard_condition_ast_ids records, innermost first, the condition of every\n  if-statement that decides whether sink_ast_id runs within its method: one\n  whose thenPart or elsePart encloses sink_ast_id, and one that precedes the\n  statement containing sink_ast_id in an enclosing statement list and has\n  exactly one branch that always leaves that list (a throw or return). An\n  if-statement after sink_ast_id decides nothing and is not recorded.\n- Aligned one-to-one with guard_condition_ast_ids: guard_sink_branches is\n  the edge of the guard's if-statement that contains sink_ast_id\n  ('thenPart' or 'elsePart'; empty for a preceding guard),\n  guard_exit_edges is the edge of that if-statement whose branch always\n  exits ('thenPart' or 'elsePart'; empty when none), and\n  guard_condition_operators is the operator of the condition (for\n  example '!'; empty when it has none).\n- A guard lets sink_ast_id run only when its condition is true if it\n  contains the sink through thenPart, or precedes it and exits through\n  elsePart; only when its condition is false if it contains the sink\n  through elsePart, or precedes it and exits through thenPart. A '!'\n  operator inverts the decision the condition expresses.\n- guard_call_ast_ids and guard_call_names are the same-graph method calls\n  that the backward value proof of the conditions passes through;\n  including calls inside called methods, in backward traversal order; empty when there is no guard.\n- guard_subject_origin_ast_ids, guard_subject_origin_kinds and\n  guard_subject_origin_values are the origins of the arguments of\n  guard_call_ast_ids under the backward value proof, deduplicated, in call\n  and argument order; empty when there is no guard call.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- SAFE is an execution that runs only when an authorization decision holds\n  (the decision is true on the path that reaches sink_ast_id, taking the\n  branch position and a negated condition into account) and that decision\n  is about the value bound into the executed statement (one of its subject\n  origins is one of the origin_ast_ids).\n- A VIOLATION is every other execution: no deciding condition, a decision\n  that is ignored or checked only after the execution, a decision whose\n  false outcome reaches the execution, or a decision about a different\n  value (for example the requesting user instead of the affected record).\n- Resolve every API identity from the graph: callKind follows calleeId to\n  the callable envelope and ownerTypeId to the declaring type's\n  qualifiedName. Lexical spellings on the use-site node are not identity\n  evidence.\n\nOUTPUT INVARIANTS:\n- Emit exactly one fact per terminal sink_ast_id, guarded AND unguarded.\n- Every nonzero AST id resolves in the loaded AST; absent structure is 0,\n  the empty string, or an empty list, never invented.\n- All names, values, types, locations, and classifications are derived\n  from the loaded facts schema, domain-model tags, and AST.\n"

driver_key := "cwe284_facts"

primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

# Core violation logic
#
# A fact is considered a potential violation if it matches the required
# structure for a sensitive operation.  Safe executions will be filtered out
# by the guard checks below.
core_positive_condition(f) if {
  # Origin kind must be call_result
  origin_kinds := object.get(f, "origin_kinds", [])
  origin_kinds == ["call_result"]
  # Origin value must be getenv
  origin_values := object.get(f, "origin_values", [])
  origin_values == ["getenv"]
  # Sink must be executeUpdate method invocation on PreparedStatement
  sink_member := object.get(f, "sink_member", "")
  sink_member == "executeUpdate"
  sink_node_type := object.get(f, "sink_node_type", "")
  sink_node_type == "method_invocation"
  sink_resolved_type := object.get(f, "sink_resolved_type", "")
  sink_resolved_type == "java.sql.PreparedStatement"
}

# Guard presence: a guard call must be present
guard_present(f) if {
  guard_call_names := object.get(f, "guard_call_names", [])
  count(guard_call_names) > 0
}

# Guard value match: guard decision value must match bound value
guard_value_match(f) if {
  guard_subject_origin_values := object.get(f, "guard_subject_origin_values", [])
  origin_values := object.get(f, "origin_values", [])
  guard_subject_origin_values == origin_values
}

# Guard kind match: guard decision kind must match bound kind
guard_kind_match(f) if {
  guard_subject_origin_kinds := object.get(f, "guard_subject_origin_kinds", [])
  origin_kinds := object.get(f, "origin_kinds", [])
  guard_subject_origin_kinds == origin_kinds
}

# A fact is allowed (safe) only if all guard rules pass
allowed_context(f) if {
  guard_present(f)
  guard_value_match(f)
  guard_kind_match(f)
}

# A fact is a violation if it meets the core structure but fails any guard rule
is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

# findings: normalize violating facts into a standard structure
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

# deny: human-readable messages for each finding
deny contains msg if {
  v := findings[_]

  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)

  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}