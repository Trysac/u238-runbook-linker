# Architecture

## runbook_linker

The library consists of three main pieces:

1. **YAML loading** (`load_rules`) scans the event stream for aliases and
   nesting depth before invoking `yaml.safe_load`, preventing alias expansion
   attacks and enforcing a maximum nesting depth.
2. **Link checking** (`check_runbooks`) resolves each alert's runbook URL
   against the local docs root or a base URL, enforces path containment,
   validates heading anchors, and optionally performs HTTP checks through a
   caller-provided callback.
3. **Slug generation** (`alert_slug` and `heading_slugs`) implements
   GitHub-style slugification for suggestion and anchor validation.

Errors are reported through a single `RunbookError` class with a machine-readable
`code`. Logging uses the module logger with a null handler; no global logging
configuration is imposed.
