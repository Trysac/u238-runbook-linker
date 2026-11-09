# runbook-linker

[![PyPI version](https://img.shields.io/pypi/v/trysac-runbook-linker)](https://pypi.org/project/trysac-runbook-linker/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-runbook-linker)](LICENSE)
[![CI](https://github.com/Trysac/u238-runbook-linker/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u238-runbook-linker/actions/workflows/ci.yml)

Check that every Prometheus alert links to a runbook that exists: local files, heading anchors, base-URL mapping, path containment and suggested links for missing ones

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-runbook-linker
# or
uv add trysac-runbook-linker
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import runbook_linker

# normalize() trims surrounding whitespace and lower-cases the text.
print(runbook_linker.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    runbook_linker.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
