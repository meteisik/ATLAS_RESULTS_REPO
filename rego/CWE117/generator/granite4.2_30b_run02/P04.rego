package policies.cwe117
import rego.v1

policy_id := "CWE117"
title := "Improper output neutralization for logs"
severity := "MEDIUM"
description := "Detect log messages that include externally controlled data without CR/LF neutralization."

driver_facts := [f | f := data.drivers.cwe117_facts.facts[_]]

core_positive_condition(f) if {
    kinds := object.get(f, "origin_kinds", [])
    values := object.get(f, "origin_values", [])
    transform_names := object.get(f, "transform_call_names", [])

    count(values) > 0
    some kind in kinds
    kind == "call_result"
    transform_names == []
}

allowed_context(f) if {
    transform_names := object.get(f, "transform_call_names", [])
    some name in transform_names
    name == "sanitize"
}

allowed_context(f) if {
    transform_names := object.get(f, "transform_call_names", [])
    some name in transform_names
    name == "replace"
}

allowed_context(f) if {
    transform_names := object.get(f, "transform_call_names", [])
    some name in transform_names
    name == "replaceAll"
}

allowed_context(f) if {
    transform_names := object.get(f, "transform_call_names", [])
    some name in transform_names
    name == "trim"
}

is_violation(f) if {
    core_positive_condition(f)
    not allowed_context(f)
}

findings := [v |
    f := driver_facts[_]
    is_violation(f)

    file := object.get(f, "file", object.get(f, "file_path", ""))
    line := object.get(f, "line", 0)
    cls := object.get(f, "class_name", "")
    method := object.get(f, "method_name", "")
    ftype := object.get(f, "fact_type", "")
    sink := object.get(f, "sink", "")

    v := {
        "policy_id": policy_id,
        "title": title,
        "severity": severity,
        "description": sprintf("CWE117 violation in %s.%s (line %v)", [cls, method, line]),
        "file": file,
        "line": line,
        "class": cls,
        "method": method,
        "fact_type": ftype,
        "sink": sink,
    }
]

deny contains msg if {
    v := findings[_]
    file := object.get(v, "file", "")
    line := object.get(v, "line", 0)
    msg := sprintf("[%s] %s at %s:%d", [v.policy_id, v.title, file, line])
}