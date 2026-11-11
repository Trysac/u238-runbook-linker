# Security

## Threat model

This library parses potentially untrusted Prometheus rule files and checks
links against a local runbook directory. It provides the following defenses:

- **Path traversal**: local runbook paths are resolved with ``Path.resolve()``
  and must remain inside the configured ``docs_root``.
- **Symlink escapes**: symlinks are resolved before the containment check, so
  a symlink pointing outside ``docs_root`` is rejected.
- **YAML alias bombs**: YAML aliases are rejected during event scanning before
  any expansion occurs.
- **Oversized input**: rule files are limited to 5 MB by default; local
  markdown files are read up to 2 MB.

## Not defended

- **TOCTOU**: a file may be swapped between the check and a later read by the
  caller.
- **Network access**: the caller-provided ``http_check`` performs network
  requests; this library never initiates them itself.
