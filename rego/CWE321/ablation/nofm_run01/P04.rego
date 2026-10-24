package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can easily detect hard-coded effective keys.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every terminal key-material sink whose effective key argument resolves to an origin, including hardcoded, external, and generated values. The Python plugin describes provenance; Rego decides the violation.\n- The key-spec constructor is the terminal occurrence (sink_ast_id). A downstream init call that consumes the constructed key-spec object is recorded as key_consumer_ast_id evidence, never as a second occurrence.\n- Discover candidates from the loaded detection contract. Application method, class, parameter, and variable names are copied output only and are never detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the terminal key argument through canonical arguments, declaredAt, initializer, valueSourceIds, writeSites, receiver_declaredAt, calleeId, parameters, returnValue, branch, operator, builder, collection, and array relationships.\n- Receiver transformations such as getBytes and toCharArray carry the receiver value; charset or formatting arguments are not key origins.\n- Support direct values, locals/fields, constant byte[] or char[] aggregates, conditional assignments, helper returns, builder chains, collection round-trips, generated material, and key objects later consumed by init.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is an effective key whose material is proven compile-time fixed: origin_kinds contains only literal/constant terminals - directly, through a helper return, a concatenation or builder of literal fragments, or a complete constant collection/array aggregate.\n- Resolve every constructor/API identity from the graph: creationKind follows class_declared to a typeIdentityKind and compares qualifiedName; callKind follows calleeId to the callable envelope name and ownerTypeId to the declaring type identity. Lexical spellings on the use-site node are not identity evidence.\n- SAFE is key material provisioned at runtime: origin_kinds contains a formal parameter, configuration/registry call result, field, or generated value and the effective key is not fully determined by literal sources.\n- A literal fragment combined with runtime data is still runtime-derived key material; a key assembled ONLY from literal fragments is compile-time fixed.\n- Algorithm markers, charset markers, mode/padding strings, IV-only values, and null are not key origins; algorithm literals are recorded separately as algorithm_literal_ast_id.\n\nOUTPUT INVARIANTS:\n- Emit exactly one fact per terminal sink (sink_ast_id), violating AND safe alike.\n- Every nonzero AST id resolves in the loaded AST; absent structure is 0 or the empty string, never invented.\n- All names, values, types, locations, and classifications are derived from the loaded facts schema, domain-model tags, and AST.\n"

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard rule: exclude facts with any non‑literal origin kind
exclude_non_literal_origin(f) if {
  some kind in f.origin_kinds
  kind != "literal"
}

# Helper: all origin_kinds are literal and list is non‑empty
all_literal_kinds(f) if {
  count(f.origin_kinds) > 0
  every kind in f.origin_kinds { kind == "literal" }
}

# Helper: all origin_values are non‑empty strings and list is non‑empty
all_nonempty_origin_values(f) if {
  count(f.origin_values) > 0
  every val in f.origin_values { val != "" }
}

# Core positive condition: sink type and origin properties
core_positive_condition(f) if {
  f.sink_member == "SecretKeySpec"
  f.sink_node_type == "class_creator"
  f.sink_resolved_type == "javax.crypto.spec.SecretKeySpec"
  all_literal_kinds(f)
  all_nonempty_origin_values(f)
}

# Violation predicate
is_violation(f) if {
  not exclude_non_literal_origin(f)
  core_positive_condition(f)
}

findings := [v |
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

  v := {
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