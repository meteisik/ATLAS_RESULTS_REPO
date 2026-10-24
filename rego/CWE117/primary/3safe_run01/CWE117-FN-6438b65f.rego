package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Describe the provenance of every log message and the transformations it passes through, so the policy layer can detect externally controlled data written to a log without CR/LF neutralization."

driver_key := "cwe117_facts"
primary_fact_type := "log_message_fact"

driver_facts := [f |
  f := data.drivers.cwe117_facts.facts[_]
]

# Neutralizer helper predicates
neutralizer(t) if { t == "replaceAll" }
neutralizer(t) if { t == "trim" }
neutralizer(t) if { t == "sanitize" }
neutralizer(t) if { t == "replace" }

# Safe if all origins are literal
safe_all_literal(f) if {
  ks := object.get(f, "origin_kinds", [])
  count(ks) > 0
  every k in ks { k == "literal" }
}

# Safe if a neutralizing transform is applied
safe_neutralized(f) if {
  ts := object.get(f, "transform_call_names", [])
  some t in ts
  neutralizer(t)
}

# Core positive condition for a violation
core_positive_condition(f) if {
  ks := object.get(f, "origin_kinds", [])
  vs := object.get(f, "origin_values", [])
  count(ks) > 0
  count(vs) > 0
  ts := object.get(f, "transform_call_names", [])
  count(ts) == 0
}

# A fact is a violation unless it is safe by either rule
is_violation(f) if {
  core_positive_condition(f)
  not safe_all_literal(f)
  not safe_neutralized(f)
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