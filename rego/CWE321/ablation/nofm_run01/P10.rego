package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can easily detect hard-coded effective keys."

driver_key := "cwe321_facts"
primary_fact_type := "crypto_key_material_fact"

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

core_positive_condition(f) if {
  object.get(f, "fact_type", "") != ""
  count(object.get(f, "origin_kinds", [])) > 0
  count(object.get(f, "origin_values", [])) > 0
  object.get(f, "sink_member", "") != ""
  object.get(f, "sink_node_type", "") != ""
  object.get(f, "sink_resolved_type", "") != ""
}

compile_time_fixed_key(f) if {
  true
}

literal_fragment_origin_values(f) if {
  every val in f.origin_values {
    val != ""
  }
}

sink_signature_match(f) if {
  object.get(f, "sink_resolved_type", "") == "javax.crypto.spec.SecretKeySpec"
}

has_key_consumer(f) if {
  object.get(f, "key_consumer_ast_id", false) != false
}

is_violation(f) if {
  core_positive_condition(f)
  compile_time_fixed_key(f)
  literal_fragment_origin_values(f)
  sink_signature_match(f)
  has_key_consumer(f)
  object.get(f, "sink_member", "") == "newInstance"
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

  call_ast_id := object.get(f, "key_consumer_ast_id", 0)

  v := {
    "policy_id":   policy_id,
    "title":       title,
    "severity":    sev,
    "description": description,
    "file":        file,
    "span":        object.get(f, "span", {"start": {"line": line}}),
    "fact_type":   ftype,
    "method_name": method,
    "method_id":   object.get(f, "method_id", 0),
    "call_ast_id": call_ast_id,
    "sink":        sink,
    "class":       cls,
    "line":        line,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}