package policies.cwe321
import rego.v1

policy_id := "CWE321"
title := "Hard-coded cryptographic key"
severity := "CRITICAL"
description := "Detects hard-coded cryptographic keys by analyzing SecretKeySpec construction sites where the key material is derived solely from compile-time literals."

driver_facts := [f | f := data.drivers.cwe321_facts.facts[_]]

core_positive_condition(f) if {
    origin_kinds := object.get(f, "origin_kinds", [])
    count(origin_kinds) > 0
    every kind in origin_kinds { kind == "literal" }

    origin_values := object.get(f, "origin_values", [])
    count(origin_values) > 0
}

allowed_context(f) if {
    origin_kinds := object.get(f, "origin_kinds", [])
    some kind in origin_kinds
    kind in {"parameter", "call_result", "field", "generated", "unknown"}
}

is_violation(f) if {
    core_positive_condition(f)
    not allowed_context(f)
}

findings := [v |
    f := driver_facts[_]
    is_violation(f)

    file_raw := object.get(f, "file", object.get(f, "file_path", ""))
    line := object.get(f, "line", 0)
    span_raw := object.get(f, "span", {"start": {"line": line}})

    fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
    method_name := object.get(f, "method_name", "")
    method_id := object.get(f, "method_id", 0)
    call_ast_id := object.get(f, "call_ast_id", 0)
    cls := object.get(f, "class_name", object.get(f, "class", ""))

    sink := object.get(f, "sink", "")

    v := {
        "policy_id":   policy_id,
        "title":       title,
        "severity":    severity,
        "description": description,
        "file":        file_raw,
        "class":       cls,
        "method":      method_name,
        "line":        line,
        "fact_type":   fact_type_val,
        "method_name": method_name,
        "method_id":   method_id,
        "call_ast_id": call_ast_id,
        "sink":        sink,
    }
]

deny contains msg if {
    v := findings[_]
    file := object.get(v, "file", "")
    span := object.get(v, "span", {})
    start := object.get(span, "start", {})
    line := object.get(start, "line", 0)
    method := object.get(v, "method_name", "")
    msg := sprintf("[%s] %s at %s:%d (method=%s)", [
        v.policy_id,
        v.title,
        file,
        line,
        method,
    ])
}