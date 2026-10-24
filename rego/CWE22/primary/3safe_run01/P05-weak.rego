package policies.cwe22
import rego.v1

policy_id := "CWE22"
title := "Path traversal"
severity := "HIGH"
description := "Detects file path constructions that incorporate externally provided input, potentially leading to path traversal vulnerabilities."

driver_key := "cwe22_facts"
primary_fact_type := "file_path_fact"

driver_facts := [f |
  f := data.drivers.cwe22_facts.facts[_]
]

#
# Helper: all origin kinds are literal
#
all_kinds_literal(f) if {
  every kind in f.origin_kinds {
    kind == "literal"
  }
}

#
# Helper: at least one non‑literal origin kind
#
has_non_literal_kind(f) if {
  some kind in f.origin_kinds
  kind != "literal"
}

#
# Helper: at least one non‑literal origin value (heuristic: not a path starting with '/')
#
has_non_literal_value(f) if {
  some val in f.origin_values
  not regex.match("^/.*", val)
}

#
# Core condition: both a non‑literal kind and a non‑literal value
#
core_positive_condition(f) if {
  has_non_literal_kind(f)
  has_non_literal_value(f)
}

#
# Safe guard: all kinds are literal
#
safe_file_path_fact(f) if {
  all_kinds_literal(f)
}

#
# Fact validity
#
valid_fact(f) if {
  f.sink_ast_id != 0
  f.sink_node_type == "class_creator"
  f.sink_resolved_type != ""
}

#
# Violation predicate
#
is_violation(f) if {
  core_positive_condition(f)
  not safe_file_path_fact(f)
  valid_fact(f)
}

#
# Finding type
#
finding_type(f) := "VIOLATION" if is_violation(f)

#
# Findings
#
findings := [finding |
  f := driver_facts[_]
  is_violation(f)
  type := finding_type(f)
  file   := object.get(f, "file", "")
  cls    := object.get(f, "class_name", "")
  method := object.get(f, "method_name", "")
  line   := object.get(f, "line", 0)
  sev    := severity
  ftype  := object.get(f, "fact_type", "")
  sink   := ""
  desc   := sprintf("Policy %s %s at %s.%s (line %v)", [
    policy_id, type, cls, method, line,
  ])
  finding := {
    "policy_id":    policy_id,
    "title":        title,
    "severity":     sev,
    "description":  desc,
    "file":         file,
    "class":        cls,
    "method":       method,
    "line":         line,
    "fact_type":    ftype,
    "sink":         sink,
    "finding_type": type
  }
]

#
# Human‑readable denial messages
#
deny contains msg if {
  v := findings[_]
  file := object.get(v, "file", "")
  line := object.get(v, "line", 0)
  msg := sprintf("[%s] %s at %s:%d", [
    v.policy_id, v.title, file, line,
  ])
}