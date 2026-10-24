package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Describe the provenance of every evaluated XPath expression so the policy layer can detect expressions built from externally controlled input."

driver_key := "cwe643_facts"
primary_fact_type := "xpath_query_fact"

driver_facts := [f |
    f := data.drivers.cwe643_facts.facts[_]
]

# Helper: true when the value looks like a compile‑time literal string
is_compile_time_literal(v) if {
    not regex.match("^[a-zA-Z_][a-zA-Z0-9_]*$", v)
}

# Guard: restrict to the intended XPath evaluate API
guard_sink_api_surface(f) if {
    object.get(f, "sink_member", "") == "evaluate"
    object.get(f, "sink_node_type", "") == "method_invocation"
    object.get(f, "sink_resolved_type", "") == "javax.xml.xpath.XPath"
}

# Guard: all origin kinds are literal
guard_all_literal_kinds(f) if {
    kinds := object.get(f, "origin_kinds", [])
    count(kinds) > 0
    every k in kinds { k == "literal" }
}

# Guard: all origin values are compile‑time literals
guard_all_literal_values(f) if {
    vals := object.get(f, "origin_values", [])
    count(vals) > 0
    every v in vals { is_compile_time_literal(v) }
}

# Safe context: both literal guards hold
allowed_context(f) if {
    guard_all_literal_kinds(f)
    guard_all_literal_values(f)
}

# Core positive condition per committed plan
core_positive_condition(f) if {
    guard_sink_api_surface(f)

    origin_kinds := object.get(f, "origin_kinds", [])
    origin_values := object.get(f, "origin_values", [])
    count(origin_kinds) > 0
    count(origin_values) > 0

    some i
    origin_kinds[i] != "literal"
    not is_compile_time_literal(origin_values[i])
}

is_violation(f) if {
    core_positive_condition(f)
    not allowed_context(f)
}

findings := [finding |
    f := driver_facts[_]
    is_violation(f)

    file   := object.get(f, "file", object.get(f, "file_path", ""))
    cls    := object.get(f, "class_name", "")
    method := object.get(f, "method_name", "")
    line   := object.get(f, "line", 0)

    sev    := object.get(f, "severity", severity)
    ftype  := object.get(f, "fact_type", object.get(f, "kind", ""))

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
    }
]

deny contains msg if {
    v := findings[_]

    file := object.get(v, "file", "")
    line := object.get(v, "line", 0)

    msg := sprintf("[%s] %s at %s:%d", [
        v.policy_id,
        v.title,
        file,
        line,
    ])
}