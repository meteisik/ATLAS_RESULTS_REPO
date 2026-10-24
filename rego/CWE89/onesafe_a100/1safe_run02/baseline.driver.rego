package drivers.cwe89_facts
import rego.v1

# HTTP-based driver for policy CWE89.
#
# Contract:
#   - OPA input is the AST JSON produced by the analyzer front-end.
#   - This driver normalizes the AST, then calls the Python analyzer
#     over HTTP, passing:
#         body = {"ast": ast_payload, "pattern": "sql_query_fact"}
#   - The analyzer (mainanalyzer) dispatches to the correct Python
#     PLUGIN.ensure_facts implementation for this policy.
#   - The analyzer returns either:
#         {"drivers": {"cwe89_facts": {"facts":[...]}}}
#     or:
#         {"facts":[...]}
#   - This driver exposes the final facts list under:
#         data.drivers.cwe89_facts.facts

default analyzer_url := "http://127.0.0.1:40127/analyze"
analyzer_url := u if {
  u := data.external_analyzer_url
  u != ""
}

# Normalize input AST:
#   - if input is an object, treat it as the AST root
#   - if input is an array, wrap as a synthetic 'program'
ast_payload := input if is_object(input)
ast_payload := {"type": "program", "children": input} if is_array(input)

# Call Python analyzer
req := {
  "method": "post",
  "url": analyzer_url,
  "headers": {"Content-Type": "application/json"},
  "body": {"ast": ast_payload, "pattern": "sql_query_fact"},
  "raise_error": false,
  # Stage 1 validates the same plugin invocation with a 30-second hard
  # execution budget.  The HTTP bridge must leave room for that validated
  # work plus JSON transport and first-load attestation overhead; otherwise a
  # healthy producer can be misreported as an empty/invalid facts stream.
  "timeout": "45s",
}

resp := http.send(req)

# Optional graph/source/fact-bound evidence travels beside the facts. Missing
# metadata stays absent; consumers may use the normal seven-field fallback.
flow_metadata := metadata if {
  resp.status_code == 200
  metadata := object.get(resp.body, "flow_metadata", null)
  is_object(metadata)
}

# Canonical facts list:
#   - Prefer wrapped form: resp.body.drivers["cwe89_facts"].facts
#   - Fallback to bare form: resp.body.facts
facts := array.concat(
  [f |
    resp.status_code == 200
    wrapped := object.get(
      object.get(
        object.get(resp.body, "drivers", {}),
        "cwe89_facts",
        {}
      ),
      "facts",
      []
    )
    count(wrapped) > 0
    f := wrapped[_]
  ],
  [f |
    resp.status_code == 200
    wrapped := object.get(
      object.get(
        object.get(resp.body, "drivers", {}),
        "cwe89_facts",
        {}
      ),
      "facts",
      []
    )
    count(wrapped) == 0
    fallback := object.get(resp.body, "facts", [])
    f := fallback[_]
  ]
)
