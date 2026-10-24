package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

primary_fact_type := "sensitive_operation_fact"

driver_facts := [f |
  f := data.drivers.cwe284_facts.facts[_]
]

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  object.get(f,"fact_type","") == "sensitive_operation_fact"
  object.get(f,"origin_kinds",[]) == ["call_result"]
  object.get(f,"origin_values",[]) == ["getenv"]
}

guard_has_call(f) if {
  guard_call_ast_ids := object.get(f,"guard_call_ast_ids",[])
  guard_call_names := object.get(f,"guard_call_names",[])
  count(guard_call_ast_ids) > 0
  count(guard_call_names) > 0
}

guard_no_negation(f) if {
  guard_condition_operators := object.get(f,"guard_condition_operators",[])
  every op in guard_condition_operators { op == "" }
}

guard_sink_then(f) if {
  guard_sink_branches := object.get(f,"guard_sink_branches",[])
  some branch in guard_sink_branches
  branch == "thenPart"
}

guard_subject_matches(f) if {
  guard_subject_origin_values := object.get(f,"guard_subject_origin_values",[])
  origin_values := object.get(f,"origin_values",[])
  guard_subject_origin_values == origin_values
}

allowed_context(f) if {
  guard_has_call(f)
  guard_no_negation(f)
  guard_sink_then(f)
  guard_subject_matches(f)
}

findings := [finding |
  f := driver_facts[_]
  is_violation(f)

  file   := object.get(f,"file",object.get(f,"file_path",""))
  cls    := object.get(f,"class_name",object.get(f,"class",""))
  method := object.get(f,"method_name",object.get(f,"method",""))
  line   := object.get(f,"line",object.get(f,"line_number",0))

  sev    := object.get(f,"severity",severity)
  ftype  := object.get(f,"fact_type",object.get(f,"kind",""))
  sink   := object.get(f,"sink","")

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
  file := object.get(v,"file","")
  line := object.get(v,"line",0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}