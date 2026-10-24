package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := `Describe cryptographic key-material provenance so the policy layer can detect
hard-coded effective keys.

NEUTRAL FACT BOUNDARY:
- Emit one neutral fact for every terminal key-material sink whose effective
  key argument resolves to an origin, including hardcoded, external, and
  generated values. The Python plugin describes provenance; Rego decides the
  violation.
- The key-spec constructor is the terminal occurrence (sink_ast_id). A
  downstream init call that consumes the constructed key-spec object is
  recorded as key_consumer_ast_id evidence, never as a second occurrence.
- Discover candidates from the loaded detection contract. Application method,
  class, parameter, and variable names are copied output only and are never
  detection gates.

BACKWARD VALUE PROOF:
- Trace the terminal key argument through canonical arguments, declaredAt,
  initializer, valueSourceIds, writeSites, receiver_declaredAt, calleeId,
  parameters, returnValue, branch, operator, builder, collection, and array
  relationships.
- Receiver transformations such as getBytes and toCharArray carry the receiver
  value; charset or formatting arguments are not key origins.
- Support direct values, locals/fields, constant byte[] or char[] aggregates,
  conditional assignments, helper returns, builder chains, collection
  round-trips, generated material, and key objects later consumed by init.

SOURCE SEMANTICS (recorded as structure,
  decided by Rego):
- A VIOLATION is an effective key whose material is proven compile-time
  fixed: origin_kinds contains only literal/constant terminals - directly,
  through a helper return, a concatenation or builder of literal fragments,
  or a complete constant collection/array aggregate.
- Resolve every constructor/API identity from the graph: creationKind follows
  class_declared to a typeIdentityKind and compares qualifiedName; callKind
  follows calleeId to the callable envelope name and ownerTypeId to the
  declaring type identity. Lexical spellings on the use-site node are not
  identity evidence.
- SAFE is key material provisioned at runtime: origin_kinds contains a
  formal parameter, configuration/registry call result, field, or generated
  value and the effective key is not fully determined by literal sources.
- A literal fragment combined with runtime data is still runtime-derived
  key material; a key assembled ONLY from literal fragments is
  compile-time fixed.
- Algorithm markers, charset markers, mode/padding strings,
  IV-only values, and null are not key origins; algorithm literals are recorded
  separately as algorithm_literal_ast_id.`

driver_key := "cwe321_facts"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard: safe emissions where at least one origin_kind is not 'literal'.
guard_safe_origin_kinds(f) if {
  kinds := object.get(f, "origin_kinds", [])
  some kind in kinds
  kind != "literal"
}

# Guard: safe emissions where origin_values contains non‑literal data.
# In current schema we cannot distinguish literal vs runtime values,
# so this guard is always false.
guard_safe_origin_values(f) if false

# Core positive condition: origin_kinds is ['literal'] or ['literal','literal']
# and origin_values is a non‑empty list.
kind_match_single(f) if {
  kinds := object.get(f, "origin_kinds", [])
  kinds == ["literal"]
  values := object.get(f, "origin_values", [])
  count(values) > 0
}

kind_match_multiple(f) if {
  kinds := object.get(f, "origin_kinds", [])
  kinds == ["literal","literal"]
  values := object.get(f, "origin_values", [])
  count(values) > 0
}

core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "crypto_key_material_fact"
  kind_match_single(f)
}
core_positive_condition(f) if {
  object.get(f, "fact_type", "") == "crypto_key_material_fact"
  kind_match_multiple(f)
}

is_violation(f) if {
  core_positive_condition(f)
  not guard_safe_origin_kinds(f)
  not guard_safe_origin_values(f)
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
  file   := object.get(v, "file", "")
  line   := object.get(v, "line", 0)
  msg    := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}