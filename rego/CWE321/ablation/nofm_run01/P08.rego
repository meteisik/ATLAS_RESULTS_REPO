package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Describe cryptographic key-material provenance so the policy layer can easily detect hard‑coded effective keys.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every terminal key-material sink whose effective key argument resolves to an origin, including hardcoded, external, and generated values. The Python plugin describes provenance; Rego decides the violation.\n- The key‑spec constructor is the terminal occurrence (sink_ast_id). A downstream init call that consumes the constructed key‑spec object is recorded as key_consumer_ast_id evidence, never as a second occurrence.\n- Discover candidates from the loaded detection contract. Application method, class, parameter, and variable names are copied output only and are never detection gates.\n\nBACKWARD VALUE PROOF:\n- Trace the terminal key argument through canonical arguments, declaredAt, initializer, valueSourceIds, writeSites, receiver_declaredAt, calleeId, parameters, returnValue, branch, operator, builder, collection, and array relationships.\n- Receiver transformations such as getBytes and toCharArray carry the receiver value; charset or formatting arguments are not key origins.\n- Support direct values, locals/fields, constant byte[] or char[] aggregates, conditional assignments, helper returns, builder chains, collection round‑trips, generated material, and key objects later consumed by init."

driver_facts := [f |
  f := data.drivers.cwe321_facts.facts[_]
]

# Guard: exclude any fact where origin_kinds contains a non‑literal kind
guard_runtime_origin_kinds(f) if {
  some kind in f.origin_kinds
  kind != "literal"
}

# Guard: exclude any fact where the key is assembled from a mix of literal fragments and runtime data
guard_runtime_fragment_concatenation(f) if {
  some val in f.origin_values
  val == ""
}

# Core positive condition: all origin_kinds are literal and all origin_values are non‑empty
core_positive_condition(f) if {
  every kind in f.origin_kinds { not kind != "literal" }
  every val in f.origin_values { not val == "" }
}

# Violation determination
is_violation(f) if {
  core_positive_condition(f)
  not guard_runtime_origin_kinds(f)
  not guard_runtime_fragment_concatenation(f)
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