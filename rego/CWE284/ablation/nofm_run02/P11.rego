package policies.cwe284
import rego.v1

policy_id := "CWE284"
title := "Missing access control"
severity := "HIGH"
description := "Describe every data-modifying statement execution, the values bound into it, and the authorization decisions that decide whether it runs, so the policy layer can detect sensitive operations that run without a matching authorization check."

driver_key := "cwe284_facts"
primary_fact_type := "sensitive_operation_fact"

driver_facts := [f | f := data.drivers.cwe284_facts.facts[_]]

getbool(o, k) := v if {
  v := object.get(o, k, false)
  v == true
}

fact_type(f) := t if {
  t := object.get(f, "fact_type", object.get(f, "kind", ""))
}

is_violation(f) if {
  core_positive_condition(f)
  not allowed_context(f)
}

core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  count(ks) == 1
  ks[0] == "call_result"

  vs := object.get(f, "origin_values", [])
  count(vs) == 1
  vs[0] == "getenv"

  sm := object.get(f, "sink_member", "")
  sm == "executeUpdate"

  sn := object.get(f, "sink_node_type", "")
  sn == "method_invocation"

  sr := object.get(f, "sink_resolved_type", "")
  sr == "java.sql.PreparedStatement"
}

allowed_context(f) if {
  gca := object.get(f, "guard_call_ast_ids", [])
  gcn := object.get(f, "guard_call_names", [])
  gca_count := count(gca)
  gca_count > 0
  gca_count == count(gcn)

  gcaids := object.get(f, "guard_condition_ast_ids", [])
  gco := object.get(f, "guard_condition_operators", [])
  gcaids_count := count(gcaids)
  gcaids_count > 0
  gcaids_count == count(gco)

  gex := object.get(f, "guard_exit_edges", [])
  gsb := object.get(f, "guard_sink_branches", [])
  gex_count := count(gex)
  gex_count > 0
  gex_count == count(gsb)

  gsao := object.get(f, "guard_subject_origin_ast_ids", [])
  gsak := object.get(f, "guard_subject_origin_kinds", [])
  gsav := object.get(f, "guard_subject_origin_values", [])
  gsao_count := count(gsao)
  gsao_count > 0
  gsao_count == count(gsak)
  gsao_count == count(gsav)
}

findings := [v |
  f := driver_facts[_]
  is_violation(f)

  file := object.get(f, "file", object.get(f, "file_path", ""))
  cls := object.get(f, "class_name", object.get(f, "class", ""))
  method := object.get(f, "method_name", object.get(f, "method", ""))
  line := object.get(f, "line", object.get(f, "line_number", 0))

  sev := object.get(f, "severity", severity)
  ftype := object.get(f, "fact_type", object.get(f, "kind", ""))
  sink := object.get(f, "sink", "")

  v := {
    "policy_id": policy_id,
    "title": title,
    "severity": sev,
    "description": description,
    "file": file,
    "class": cls,
    "method": method,
    "line": line,
    "fact_type": ftype,
    "sink": sink,
  }
]

deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  method := object.get(v, "method", "")
  msg := sprintf("[%s] %s at %s:%d (method=%s)", [
    v.policy_id,
    v.title,
    file,
    line,
    method,
  ])
}