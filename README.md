# trysac-runbook-linker

<!-- existing badges are kept; no metrics or users are invented -->

Check that every Prometheus alert links to a runbook that exists: local files,
heading anchors, base-URL mapping, path containment and suggested links for
missing ones.

## Usage

```python
from pathlib import Path
from runbook_linker import load_rules, check_runbooks

rules = load_rules(Path("rules.yml").read_text())
findings = check_runbooks(
    rules, docs_root=Path("docs/runbooks"), base_url="https://docs.example.test/runbooks"
)
for f in findings:
    if f.status != "ok":
        print(f.alert, f.status, f.detail)
```

## CLI

```bash
python -m runbook_linker check rules.yml --docs docs/runbooks \
    --base-url https://docs.example.test/runbooks
```

Returns 0 when every alert is ok, 1 if any link is not ok, and 2 for errors.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model.
