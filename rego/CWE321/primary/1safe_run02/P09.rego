package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can detect hard-coded effective keys.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every terminal key-material sink whose effective key argument resolves to an origin, including hardcoded, external, and generated values. The Python plugin describes provenance; Rego decides the violation.\n- The key-spec constructor is the terminal occurrence (sink_ast_id). A downstream init call that consumes the constructed key-spec object is recorded as key_consumer_ast_id evidence, never as a second occurrence.\n- Discover candidates from the loaded detection contract. Application method,\n  class, parameter, and variable names are copied output only and are never\n  detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the terminal key argument through canonical arguments, declaredAt,\n  initializer, valueSourceIds, writeSites, receiver_declaredAt, calleeId,\n  parameters, returnValue, branch, operator, builder, collection, and array\n  relationships.\n- Receiver transformations such as getBytes and toCharArray carry the receiver\n  value; charset or formatting arguments are not key origins.\n- Support direct values, locals/fields, constant byte[] or char[] aggregates,\n  conditional assignments, helper returns, builder chains, collection\n  round-trips, generated material, and key objects later consumed by init.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is an effective key whose material is proven compile-time\n  fixed: origin_kinds contains only literal/constant terminals - directly,\n  through a helper return, a concatenation or builder of literal fragments,\n  or a complete constant collection/array aggregate.\n- Resolve every constructor/API identity from the graph: creationKind follows\n  class_declared to a typeIdentityKind and compares qualifiedName; callKind\n  follows calleeId to the callable envelope name and ownerTypeId to the\n  declaring type identity. Lexical spellings on the use-site node are not\n  identity evidence.\n- SAFE is key material provisioned at runtime: origin_kinds contains a\n  formal parameter, configuration/registry call result, field, or generated\n  value and the effective key is not fully determined by literal sources.\n- A literal fragment combined with runtime data is still runtime-derived\n  key material; a key assembled ONLY from literal fragments is\n  compile-time fixed.\n- Algorithm markers, charset markers, mode/padding strings, IV-only\n  values, and null are not key origins; algorithm literals are recorded\n  separately as algorithm_literal_ast_id."

driver_key := "cwe321_facts"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard: marks fact as safe if any origin_kind is not 'literal'
guard_non_literal_origin_kind(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

# Guard: marks fact as safe if any origin_value is empty (non‑literal)
guard_non_literal_origin_value(f) if {
  values := object.get(f, "origin_values", [])
  some val in values
  val == ""
}

# Core positive condition: all origin_kinds are 'literal' and all origin_values are non‑empty
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "crypto_key_material_fact"
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every kind in kinds { kind == "literal" }
  values := object.get(f, "origin_values", [])
  count(values) > 0
  every val in values { val != "" }
}

# A fact is a violation if it satisfies the core condition and no guard triggers
is_violation(f) if {
  core_positive_condition(f)
  not guard_non_literal_origin_kind(f)
  not guard_non_literal_origin_value(f)
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