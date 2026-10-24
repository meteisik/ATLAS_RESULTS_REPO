package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects cryptographic keys that are hard-coded as literal values in the source code."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  # The sink is identified by the resolved type of the construction site.
  # This covers both direct constructors and factory methods.
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.SecretKeySpec"

  # Provenance must be explicitly tracked and exclusively composed of compile-time fixed types.
  kinds := object.get(f, "origin_kinds", [])
  count(kinds) > 0
  every k in kinds {
    k in {"literal", "constant"}
  }

  # Origin values must be present.
  values := object.get(f, "origin_values", [])
  count(values) > 0
}

allowed_context(f) if {
  # runtime_provenance_guard: Suppress findings if any origin is derived from runtime sources.
  # Per SOURCE SEMANTICS, any runtime source (parameter, field, call_result, generated) makes it safe.
  kinds := object.get(f, "origin_kinds", [])
  some k in kinds
  not k in {"literal", "constant"}
}

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

  desc := sprintf("Policy %s violation at %s.%s (line %v): Hard-coded cryptographic key material detected.", [
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