package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Describe the provenance of every file-system path construction so the\npolicy layer can detect paths built from externally controlled input.\n\nNEUTRAL FACT BOUNDARY:\n- Emit one neutral fact for every file path construction (for example\n  new java.io.File(path)) whose path argument resolves to origins, including\n  constant, external, and parameter values. The Python plugin describes\n  provenance;\n  Rego decides the violation.\n- The path construction is the terminal occurrence\n  (sink_ast_id); its path argument is path_arg_ast_id. A downstream creation\n  or call that receives the constructed File (for example a FileInputStream)\n  is recorded as file_consumer_ast_id evidence, never as a second occurrence.\n\nSOURCE SEMANTICS (recorded as structure, decided by Rego):\n- A VIOLATION is a path whose origins include a runtime-provided value: a\n  call_result of an external read, a field without a constant writer, or an\n  unresolved formal parameter, appended without validation.\n- SAFE is a path whose origins are all literal/constant terminals. A\n  constant root combined with runtime data is still runtime-derived.\n"

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

#
# Helper predicates for origin kinds
#
origin_kinds_has_call_result(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind == "call_result"
}

origin_kinds_has_nonliteral(f) if {
  some kind in object.get(f, "origin_kinds", [])
  kind != "literal"
}

#
# Helper predicate for origin values
#
origin_values_has_nonliteral(f) if {
  some val in object.get(f, "origin_values", [])
  val == "getenv"
}

#
# Guard predicates
#
guard_literal_only(f) if {
  every kind in object.get(f, "origin_kinds", []) { kind == "literal" }
}

guard_no_runtime_values(f) if {
  every val in object.get(f, "origin_values", []) { val != "getenv" }
}

#
# Core positive condition
#
core_positive_condition(f) if {
  origin_kinds_has_call_result(f)
  origin_values_has_nonliteral(f)
}

core_positive_condition(f) if {
  origin_kinds_has_nonliteral(f)
  origin_values_has_nonliteral(f)
}

#
# Violation determination
#
is_violation(f) if {
  core_positive_condition(f)
  not guard_literal_only(f)
  not guard_no_runtime_values(f)
}

#
# Findings
#
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

#
# Human‑readable deny messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}