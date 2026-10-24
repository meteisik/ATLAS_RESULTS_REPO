package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := `Describe the provenance of every file-system path construction so the
policy layer can detect paths built from externally controlled input.

NEUTRAL FACT BOUNDARY:
- Emit one neutral fact for every file path construction (for example
  new java.io.File(path)) whose path argument resolves to origins, including
  constant, external, and parameter values. The Python plugin describes
  provenance; Rego decides the violation.
- The path construction is the terminal occurrence (sink_ast_id); its path
  argument is path_arg_ast_id. A downstream creation or call that receives
  the constructed file (for example a FileInputStream) is recorded as
  file_consumer_ast_id evidence, never as a second occurrence.
- Discover candidates from the loaded detection contract. Application method,
  class, parameter, and variable names are copied output only and are never
  detection gates.

BACKWARD VALUE PROOF:
- Trace the path argument through declaredAt, initializer, valueSourceIds,
  argumentOfParameter (formal parameter to the caller argument), calleeId and
  returnValue, operator (op1/op2), cast, array, collection, field, and
  receiver relationships, across methods and classes of the analyzed file.
- A concatenation retains every outermost operand origin in operand order,
  including the constant root directory.
- Receiver transformations carry the receiver value; delimiter, charset, and
  index arguments are not origins.
- An external call without a value receiver (an environment, property,
  console, network, or request read) is itself a call_result origin; its
  arguments are not followed.

SOURCE SEMANTICS (recorded as structure, decided by Rego):
- A VIOLATION is a path whose origins include a runtime-provided value: a
  call_result of an external read, a field without a constant writer, or an
  unresolved formal parameter, appended without validation.
- SAFE is a path whose origins are all literal/constant terminals. A
  constant root combined with runtime data is still runtime-derived.
- Resolve every constructor/API identity from the graph: creationKind
  and callKind follow calleeId to the callable envelope and ownerTypeId to the
  declaring type's qualifiedName. Lexical spellings on the use-site node are
  not identity evidence.

OUTPUT INVARIANTS:
- Emit exactly one fact per terminal sink_ast_id, violating AND safe alike.
- Every nonzero AST id resolves in the loaded AST; absent structure is 0,
  the empty string, or an empty list, never invented.
- All names, values, types, locations, and classifications are derived
  from the loaded facts schema, domain-model tags, and AST.`

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

# Small boolean-field helper:
getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

# Extract the fact_type (or kind) if present.
fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

# Core violation logic
core_positive_condition(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  count(kinds) > 0
  count(values) > 0
  count(kinds) == count(values)
  some i
  kind := kinds[i]
  value := values[i]
  kind == "call_result"
  value == "getenv"
}

# Guard rule: allow paths constructed solely from literal origins
allow_literal_only_paths(f) if {
  kinds := object.get(f, "origin_kinds", [])
  values := object.get(f, "origin_values", [])
  kinds == ["literal"]
  every v in values { v != "" }
}

allowed_context(f) if allow_literal_only_paths(f)

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f, "file", object.get(f, "file_path", ""))
  cls    := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line   := object.get(f, "line", object.get(f, "line_number", 0))

  sev    := severity
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

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}