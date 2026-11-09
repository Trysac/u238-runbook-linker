"""Link Prometheus alerts to runbooks and verify the links.

This library reads Prometheus rule files, extracts alert runbook URLs from
the ``runbook_url`` annotation, resolves them against a local runbook
directory or a remote base URL, and reports missing, broken, or
anchor-missing links. It also suggests runbook links for alerts that lack an
annotation when a file with the slugified alert name exists.

Security model (see docs/SECURITY.md):

* Defended: path traversal (resolved paths must stay under ``docs_root``),
  symlink escapes (symlinks are resolved before the containment check),
  YAML alias bombs (aliases are rejected), and oversized input (default
  5 MB).
* Not defended: TOCTOU between link checking and later file access, and
  network access performed by the caller-provided ``http_check``.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import re
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, urlsplit

import yaml

__all__ = [
    "AlertRule",
    "Finding",
    "RunbookError",
    "alert_slug",
    "check_runbooks",
    "heading_slugs",
    "load_rules",
    "main",
]

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Maximum input size for YAML rule files and local markdown files.
MAX_RULES_BYTES = 5_000_000
MAX_LOCAL_FILE_BYTES = 2_000_000

# Maximum YAML nesting depth allowed.
MAX_YAML_DEPTH = 64

# Valid HTTP status codes for an "ok" external URL.
HTTP_OK_MIN = 200
HTTP_OK_MAX = 399

_ANNOTATION_KEY = "runbook_url"


class RunbookError(Exception):
    """Base error for the runbook linker."""

    def __init__(
        self, code: Literal["input_too_large", "invalid_yaml", "invalid_rules"], message: str = ""
    ) -> None:
        self.code = code
        self.message = message[:200] if message else ""
        super().__init__(self.message or self.code)


@dataclasses.dataclass(frozen=True)
class AlertRule:
    """A single Prometheus alert rule extracted from a rule file."""

    alert: str
    runbook_url: str | None = None
    group: str = ""


@dataclasses.dataclass(frozen=True)
class Finding:
    """Result of checking one alert's runbook link."""

    alert: str
    status: Literal[
        "ok",
        "missing",
        "broken",
        "anchor_missing",
        "outside_root",
        "invalid_url",
        "unchecked",
        "templated",
    ]
    url: str | None = None
    suggestion: str | None = None
    detail: str = ""


def _decode_bytes(text: str | bytes) -> str:
    """Decode bytes input as UTF-8, replacing invalid sequences."""
    if isinstance(text, bytes):
        return text.decode("utf-8", errors="replace")
    return text


def _scan_yaml(text: str | bytes) -> None:
    """Scan YAML event stream for aliases and excessive nesting depth.

    Raises:
        RunbookError: with code ``invalid_yaml`` if an alias is found,
            nesting exceeds ``MAX_YAML_DEPTH``, or the YAML is malformed.
    """
    try:
        events = yaml.parse(text)
        depth = 0
        for event in events:
            if isinstance(event, yaml.AliasEvent):
                raise RunbookError("invalid_yaml", "YAML aliases are not allowed")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > MAX_YAML_DEPTH:
                    raise RunbookError("invalid_yaml", f"YAML nesting exceeds {MAX_YAML_DEPTH}")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
    except yaml.YAMLError as exc:
        raise RunbookError("invalid_yaml", f"Invalid YAML: {exc}") from exc


def _safe_load_yaml(text: str | bytes) -> object:
    """Parse YAML after security scan, raising RunbookError on any YAML error."""
    _scan_yaml(text)
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RunbookError("invalid_yaml", f"Invalid YAML: {exc}") from exc


def _as_dict(value: object, context: str) -> dict[object, object]:
    if not isinstance(value, dict):
        raise RunbookError("invalid_rules", f"{context} must be a mapping")
    return value


def _as_list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise RunbookError("invalid_rules", f"{context} must be a list")
    return value


def load_rules(text: str | bytes, *, max_bytes: int = MAX_RULES_BYTES) -> list[AlertRule]:
    """Parse a Prometheus rule file and return its alert rules.

    Args:
        text: YAML content of the rule file.
        max_bytes: Maximum input size in bytes before raising ``input_too_large``.

    Returns:
        List of :class:`AlertRule` objects, preserving file order.

    Raises:
        RunbookError: ``input_too_large`` if the input exceeds ``max_bytes``;
            ``invalid_yaml`` for YAML syntax errors or forbidden aliases;
            ``invalid_rules`` if the structure is not Prometheus rule format.
    """
    raw = text if isinstance(text, bytes) else text.encode("utf-8")
    if len(raw) > max_bytes:
        raise RunbookError("input_too_large", f"Input exceeds {max_bytes} bytes")

    data = _safe_load_yaml(text)
    top = _as_dict(data, "top level")
    groups = _as_list(top.get("groups", []), "groups")

    result: list[AlertRule] = []
    for group_idx, group_obj in enumerate(groups):
        group = _as_dict(group_obj, f"group {group_idx}")
        group_name = group.get("name", "")
        if not isinstance(group_name, str):
            group_name = ""
        rules = _as_list(group.get("rules", []), f"group {group_idx} rules")
        for rule_idx, rule_obj in enumerate(rules):
            rule = _as_dict(rule_obj, f"rule {group_idx}.{rule_idx}")
            if "record" in rule:
                continue  # recording rule, not an alert
            if "alert" not in rule:
                raise RunbookError(
                    "invalid_rules", f"rule {group_idx}.{rule_idx} has neither alert nor record"
                )
            alert = rule["alert"]
            if not isinstance(alert, str):
                raise RunbookError(
                    "invalid_rules", f"alert {group_idx}.{rule_idx} must be a string"
                )
            annotations = rule.get("annotations")
            if annotations is None:
                annotations = {}
            annotations = _as_dict(annotations, f"annotations for {alert}")
            url_value = annotations.get(_ANNOTATION_KEY)
            runbook_url: str | None = None
            if url_value is not None:
                if not isinstance(url_value, str):
                    raise RunbookError("invalid_rules", f"runbook_url for {alert} must be a string")
                runbook_url = url_value
            result.append(AlertRule(alert=alert, runbook_url=runbook_url, group=group_name))
    return result


def alert_slug(name: str) -> str:
    """Convert an alert name to a GitHub-style slug.

    Inserts hyphens between lower/digit and upper-case transitions, and
    between an upper-case run and an upper-case letter followed by a
    lower-case one, then lowercases the result.
    """
    result_chars: list[str] = []
    for i, ch in enumerate(name):
        if ch.isupper() and (
            (i > 0 and (name[i - 1].islower() or name[i - 1].isdigit()))
            or (i > 0 and name[i - 1].isupper() and i + 1 < len(name) and name[i + 1].islower())
        ):
            result_chars.append("-")
        result_chars.append(ch.lower())
    return "".join(result_chars)


def heading_slugs(markdown: str) -> list[str]:
    """Return GitHub-style slugs for every ATX heading outside code fences.

    ATX headings are lines with 1 to 6 ``#`` characters followed by a space,
    optionally preceded by up to 3 spaces. Fenced code blocks delimited by
    ``` or ~~~ are ignored. Duplicate slugs get ``-1``, ``-2``, ... suffixes.
    """
    slugs: list[str] = []
    seen: dict[str, int] = {}
    in_fence = False
    fence_char = ""
    fence_len = 0
    heading_re = re.compile(r"^( {0,3})(#{1,6}) (.*)$")

    for line in markdown.splitlines():
        stripped = line.lstrip()
        # Handle fenced code blocks
        if not in_fence:
            fence_match = re.match(r"^(```+|~~~+)", stripped)
            if fence_match:
                in_fence = True
                fence_char = fence_match.group(1)[0]
                fence_len = len(fence_match.group(1))
                continue
        else:
            # Check for closing fence: same char, at least same length, rest only spaces
            if stripped.startswith(fence_char * fence_len):
                rest = stripped[fence_len:]
                if rest.strip() == "":
                    in_fence = False
            continue

        if in_fence:
            continue

        m = heading_re.match(line)
        if not m:
            continue
        heading_text = m.group(3)
        # Lowercase and remove trailing '#' run
        lower = heading_text.lower()
        lower = re.sub(r"#+$", "", lower).rstrip()
        # Remove characters other than word chars, spaces, and hyphens
        cleaned = re.sub(r"[^\w\s-]", "", lower)
        # Replace spaces with hyphens
        slug = cleaned.replace(" ", "-")
        # Unique suffix for duplicates
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        if count:
            slug = f"{slug}-{count}"
        slugs.append(slug)
    return slugs


def _normalize_base_url(base_url: str | None) -> str | None:
    if base_url is None:
        return None
    return base_url.rstrip("/")


def _remove_query_and_fragment_from_local(url_part: str) -> tuple[str, str | None]:
    """Split a local URL part into path and fragment, removing query."""
    fragment = None
    if "#" in url_part:
        url_part, fragment = url_part.split("#", 1)
    if "?" in url_part:
        url_part = url_part.split("?", 1)[0]
    return url_part, fragment


def _resolve_local_path(docs_root: Path, raw_path: str) -> Path | None:
    """Decode and resolve a local path, returning None if outside docs_root.

    Paths that cannot be resolved (for example a percent-decoded NUL byte)
    return ``None`` so they are reported instead of raising.
    """
    decoded = unquote(raw_path)
    try:
        candidate = (docs_root / decoded).resolve()
        docs_resolved = docs_root.resolve()
    except (OSError, ValueError):
        return None
    if not candidate.is_relative_to(docs_resolved):
        return None
    return candidate


def _read_local_file(path: Path) -> str:
    """Read up to MAX_LOCAL_FILE_BYTES bytes, decode UTF-8 replacing errors."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_LOCAL_FILE_BYTES + 1)
        if len(data) > MAX_LOCAL_FILE_BYTES:
            data = data[:MAX_LOCAL_FILE_BYTES]
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def check_runbooks(
    rules: Sequence[AlertRule],
    *,
    docs_root: Path,
    base_url: str | None = None,
    http_check: Callable[[str], int] | None = None,
    annotation: str = _ANNOTATION_KEY,
) -> list[Finding]:
    """Check a sequence of alert rules against local docs and remote URLs.

    Args:
        rules: Alert rules to check.
        docs_root: Root directory of local runbook markdown files.
        base_url: Base URL that maps to ``docs_root``. Trailing slashes are
            ignored. URLs starting with ``base_url + '/'`` are treated as local.
        http_check: Callable returning an HTTP status code for external URLs.
            If omitted, external URLs get status ``unchecked``.
        annotation: The annotation key used for runbook URLs (default
            ``runbook_url``). Currently only used for documentation; URLs are
            already extracted by :func:`load_rules`.

    Returns:
        Findings sorted by group, then alert.
    """
    del annotation  # reserved for future use
    base_norm = _normalize_base_url(base_url)
    docs_root = docs_root.expanduser()

    sorted_rules = sorted(rules, key=lambda r: (r.group, r.alert))
    findings: list[Finding] = []

    for rule in sorted_rules:
        alert = rule.alert
        url = rule.runbook_url

        if url is None:
            # Missing URL: suggest if a file with slugged alert name exists
            slug = alert_slug(alert)
            suggestion = None
            candidate_rel = Path(f"{slug}.md")
            candidate_abs = (docs_root / candidate_rel).resolve()
            if candidate_abs.is_file():
                if base_norm is not None:
                    suggestion = f"{base_norm}/{slug}.md"
                else:
                    suggestion = str(candidate_rel)
            findings.append(
                Finding(
                    alert=alert,
                    status="missing",
                    suggestion=suggestion,
                    detail="no runbook_url annotation",
                )
            )
            continue

        if "{{" in url:
            findings.append(
                Finding(alert=alert, status="templated", url=url, detail="URL contains a template")
            )
            continue

        try:
            scheme = urlsplit(url).scheme.lower()
        except ValueError:
            findings.append(
                Finding(
                    alert=alert,
                    status="invalid_url",
                    url=url,
                    detail="malformed URL",
                )
            )
            continue
        if scheme not in ("", "http", "https"):
            findings.append(
                Finding(
                    alert=alert,
                    status="invalid_url",
                    url=url,
                    detail=f"unsupported scheme {scheme!r}",
                )
            )
            continue

        is_local = False
        local_path_raw: str | None = None

        # Local relative path (no scheme, not protocol-relative)
        if scheme == "" and not url.startswith("//"):
            local_path_raw = url
            is_local = True
        # base_url mapping
        elif base_norm is not None and url.startswith(base_norm + "/"):
            remainder = url[len(base_norm) + 1 :]
            local_path_raw = remainder
            is_local = True

        if is_local and local_path_raw is not None:
            local_path_part, local_fragment = _remove_query_and_fragment_from_local(local_path_raw)
            resolved = _resolve_local_path(docs_root, local_path_part)
            if resolved is None:
                findings.append(
                    Finding(
                        alert=alert,
                        status="outside_root",
                        url=url,
                        detail="path is outside docs root",
                    )
                )
                continue
            if not resolved.is_file():
                findings.append(
                    Finding(alert=alert, status="broken", url=url, detail="file not found")
                )
                continue
            if local_fragment is not None:
                content = _read_local_file(resolved)
                if not content:
                    # Cannot read file; treat as broken
                    findings.append(
                        Finding(alert=alert, status="broken", url=url, detail="cannot read file")
                    )
                    continue
                slugs = heading_slugs(content)
                if local_fragment not in slugs:
                    findings.append(
                        Finding(
                            alert=alert,
                            status="anchor_missing",
                            url=url,
                            detail=f"anchor #{local_fragment} not found",
                        )
                    )
                    continue
            findings.append(Finding(alert=alert, status="ok", url=url))
            continue

        # External URL (scheme http/https not matching base_url)
        if http_check is None:
            findings.append(
                Finding(alert=alert, status="unchecked", url=url, detail="no http_check provided")
            )
            continue
        try:
            status_code = http_check(url)
        except Exception as exc:
            logger.debug("http_check failed for %s: %s", url, exc)
            findings.append(Finding(alert=alert, status="broken", url=url, detail="check failed"))
            continue
        if HTTP_OK_MIN <= status_code <= HTTP_OK_MAX:
            findings.append(Finding(alert=alert, status="ok", url=url))
        else:
            findings.append(
                Finding(alert=alert, status="broken", url=url, detail=f"HTTP status {status_code}")
            )

    return findings


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runbook-linker", description="Verify Prometheus alert runbook links"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check", help="check a rule file")
    check_parser.add_argument("rules", help="path to Prometheus rule file")
    check_parser.add_argument(
        "--docs", required=True, type=Path, help="directory containing runbook markdown files"
    )
    check_parser.add_argument("--base-url", default=None, help="base URL mapping to --docs")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Returns 0 if every alert is ok, 1 if any finding is not ok,
    2 for any error (unreadable rules file, invalid YAML, etc.).
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    if args.command != "check":
        parser.error("only check command is supported")

    try:
        rules_text = Path(args.rules).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read rules file: {exc}", file=sys.stderr)
        return 2

    try:
        rules = load_rules(rules_text)
    except RunbookError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = check_runbooks(rules, docs_root=args.docs, base_url=args.base_url)
    non_ok = [f for f in findings if f.status != "ok"]
    for f in non_ok:
        print(f"{f.alert}\t{f.status}\t{f.detail}")
    return 1 if non_ok else 0
