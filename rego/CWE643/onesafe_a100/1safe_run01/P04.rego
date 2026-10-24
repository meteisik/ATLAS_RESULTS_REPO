package policies.cwe643
import rego.v1

policy_id := "CWE643"
title := "XPath injection"
severity := "HIGH"
description := "Detects XPath expressions built from externally controlled input."

driver_facts := [f | f := data.drivers.cwe643_facts.facts[_]]

core_positive_condition(f) if {
    o_kinds := object.get(f, "origin_kinds", [])
    o_vals := object.get(f, "origin_values", [])
    count(o_kinds) > 0
    count(o_kinds) == count(o_vals)

    some idx
    kind := o_kinds[idx]
    val := o_vals[idx]
    kind == "call_result"
    val == "getenv"

    sink_member := object.get(f, "sink_member", "")
    sink_node_type := object.get(f, "sink_node_type", "")
    sink_resolved_type := object.get(f, "sink_resolved_type", "")
    sink_member == "evaluate"
    sink_node_type == "method_invocation"
    sink_resolved_type == "javax.xml.xpath.XPath"
}

allowed_context(f) if false

is_violation(f) if {
    core_positive_condition(f)
    not allowed_context(f)
}

build_finding(f) := v if {
    file := object.get(f, "file", object.get(f, "file_path", ""))
    line := object.get(f, "line", 0)
    span := object.get(f, "span", {"start": {"line": line}})
    fact_type_val := object.get(f, "fact_type", object.get(f, "kind", ""))
    method_name := object.get(f, "method_name", "")
    method_id := object.get(f, "method_id", 0)
    call_ast_id := object.get(f, "call_ast_id", 0)
    sink := object.get(f, "sink", "")
    v := {
        "policy_id":   policy_id,
        "title":       title,
        "severity":    severity,
        "description": description,
        "file":        file,
        "span":        span,
        "fact_type":   fact_type_val,
        "method_name": method_name,
        "method_id":   method_id,
        "call_ast_id": call_ast_id,
        "sink":        sink,
    }
}

violation_map := {key: v |
    f := driver_facts[_]
    is_violation(f)
    key := sprintf("%v", [f.sink_ast_id])
    v := build_finding(f)
}

findings := [v | v := violation_map[_]]

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