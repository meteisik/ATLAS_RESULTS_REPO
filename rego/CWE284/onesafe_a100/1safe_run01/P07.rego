package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

core_positive_condition(f) if {
  originKinds := object.get(f, "origin_kinds", [])
  originKinds == ["call_result"]
  originValues := object.get(f, "origin_values", [])
  originValues == ["getenv"]
  rawPrepare := object.get(f, "prepare_call_ast_id", 0)
  rawPrepare != 0
  rawReceiver := object.get(f, "receiver_decl_ast_id", 0)
  rawReceiver != 0
}

allowed_context(f) if {
  rawPrepare := object.get(f, "prepare_call_ast_id", 0)
  rawPrepare == 0
}
allowed_context(f) if {
  rawPrepare := object.get(f, "prepare_call_ast_id", 0)
  rawPrepare == null
}
allowed_context(f) if {
  rawReceiver := object.get(f, "receiver_decl_ast_id", 0)
  rawReceiver == 0
}
allowed_context(f) if {
  rawReceiver := object.get(f, "receiver_decl_ast_id", 0)
  rawReceiver == null
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))
  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")
  sinkMember := object.get(f, "sink_member", "")
  desc := sprintf("Policy %s violation at %s.%s (line %v)", [policy_id, cls, method, line])

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
    "sink_member": sinkMember
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}