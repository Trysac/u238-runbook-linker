# Use PyYAML with alias rejection for secure YAML parsing

Status: accepted (generated, pending human review)

## Context

Prometheus rule files are YAML documents. PyYAML's safe_load expands aliases, which can lead to billion-laughs style resource exhaustion. The specification requires rejecting any alias usage.

## Decision

Scan the YAML event stream with yaml.parse before safe_load; reject AliasEvent and enforce a maximum nesting depth of 64. Then parse with safe_load, which is safe because no aliases remain.

## Consequences

Alias support is intentionally disabled. Rule files that use YAML aliases will fail with `invalid_yaml`. Deeply nested documents are also rejected. The event scan adds minimal overhead.
