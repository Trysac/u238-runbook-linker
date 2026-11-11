from __future__ import annotations

import os
from pathlib import Path

import pytest

from runbook_linker import (
    AlertRule,
    Finding,
    RunbookError,
    alert_slug,
    check_runbooks,
    heading_slugs,
    load_rules,
    main,
)

# Helpers to create rule files and docs directories


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def make_rule_yaml(groups: list[dict]) -> str:
    import yaml

    return yaml.safe_dump({"groups": groups}, sort_keys=False)


@pytest.fixture
def tmp_docs(tmp_path: Path) -> Path:
    docs = tmp_path / "docs"
    docs.mkdir()
    return docs


# ---------- load_rules ----------


def test_load_rules_basic():
    yaml_text = """
groups:
- name: group1
  rules:
  - alert: HighCPU
    expr: up == 0
    annotations:
      runbook_url: https://example.com/runbook.md
  - alert: NoURL
    expr: up == 0
"""
    rules = load_rules(yaml_text)
    assert rules == [
        AlertRule(alert="HighCPU", runbook_url="https://example.com/runbook.md", group="group1"),
        AlertRule(alert="NoURL", runbook_url=None, group="group1"),
    ]


def test_load_rules_empty_annotations():
    yaml_text = """
groups:
- name: g
  rules:
  - alert: A
    expr: up==0
    annotations: {}
"""
    rules = load_rules(yaml_text)
    assert rules[0].runbook_url is None


def test_load_rules_bytes_input():
    yaml_text = b"""
groups:
- name: g
  rules:
  - alert: A
    expr: up==0
"""
    rules = load_rules(yaml_text)
    assert rules[0].alert == "A"


def test_load_rules_recording_rule_skipped():
    yaml_text = """
groups:
- name: g
  rules:
  - record: some:metric
    expr: up
  - alert: B
    expr: up==0
"""
    rules = load_rules(yaml_text)
    assert len(rules) == 1
    assert rules[0].alert == "B"


def test_load_rules_multiple_groups_and_order():
    yaml_text = """
groups:
- name: g2
  rules:
  - alert: A2
    expr: up==0
- name: g1
  rules:
  - alert: A1
    expr: up==0
"""
    rules = load_rules(yaml_text)
    assert [r.group for r in rules] == ["g2", "g1"]
    assert [r.alert for r in rules] == ["A2", "A1"]


def test_load_rules_size_limit():
    big = "a" * 5_000_001
    with pytest.raises(RunbookError) as exc_info:
        load_rules(big)
    assert exc_info.value.code == "input_too_large"


def test_load_rules_alias_rejected():
    yaml_text = """
groups:
- name: g
  rules:
  - alert: A
    expr: up==0
    annotations: &x
      runbook_url: http://x
  - alert: B
    expr: up==0
    annotations: *x
"""
    with pytest.raises(RunbookError) as exc_info:
        load_rules(yaml_text)
    assert exc_info.value.code == "invalid_yaml"


def test_load_rules_depth_limit():
    deep = "[" * 100 + "1" + "]" * 100
    yaml_text = f"groups:\n- name: g\n  rules:\n  - alert: A\n    expr: up==0\n  deep: {deep}\n"
    with pytest.raises(RunbookError) as exc_info:
        load_rules(yaml_text)
    assert exc_info.value.code == "invalid_yaml"


def test_load_rules_groups_not_list():
    yaml_text = "groups: notalist\n"
    with pytest.raises(RunbookError) as exc_info:
        load_rules(yaml_text)
    assert exc_info.value.code == "invalid_rules"


def test_load_rules_rule_without_alert_or_record():
    yaml_text = """
groups:
- name: g
  rules:
  - expr: up
"""
    with pytest.raises(RunbookError) as exc_info:
        load_rules(yaml_text)
    assert exc_info.value.code == "invalid_rules"


def test_load_rules_non_string_runbook_url():
    yaml_text = """
groups:
- name: g
  rules:
  - alert: A
    expr: up==0
    annotations:
      runbook_url: 123
"""
    with pytest.raises(RunbookError) as exc_info:
        load_rules(yaml_text)
    assert exc_info.value.code == "invalid_rules"


def test_load_rules_invalid_yaml_syntax():
    yaml_text = "groups: [unclosed\n"
    with pytest.raises(RunbookError) as exc_info:
        load_rules(yaml_text)
    assert exc_info.value.code == "invalid_yaml"


# ---------- heading_slugs ----------


def test_heading_slugs_acceptance():
    md = "# High CPU Usage!\n## Steps\n## Steps\n```\n# not a heading\n```"
    assert heading_slugs(md) == ["high-cpu-usage", "steps", "steps-1"]


def test_heading_slugs_ignores_fenced_code():
    md = "# Real\n```\n## Fake\n```\n~~~\n### Also fake\n~~~"
    assert heading_slugs(md) == ["real"]


def test_heading_slugs_unicode():
    md = "## Привет мир"
    assert heading_slugs(md) == ["привет-мир"]


def test_heading_slugs_trailing_hash_removed():
    md = "### Title ##\n## Other#"
    assert heading_slugs(md) == ["title", "other"]


def test_heading_slugs_duplicates_numbering():
    md = "# A\n# A\n# A"
    assert heading_slugs(md) == ["a", "a-1", "a-2"]


def test_heading_slugs_indented_code_not_heading():
    md = "    # indented code"
    assert heading_slugs(md) == []


# ---------- alert_slug ----------


def test_alert_slug_acceptance():
    assert alert_slug("HighCPUUsage") == "high-cpu-usage"
    assert alert_slug("KubePodCrashLooping") == "kube-pod-crash-looping"
    assert alert_slug("Disk95Percent") == "disk95-percent"


def test_alert_slug_additional():
    assert alert_slug("lowercase") == "lowercase"
    assert alert_slug("ABC") == "abc"
    assert alert_slug("A1B") == "a1-b"


# ---------- check_runbooks ----------


def test_missing_with_base_url_and_file_exists(tmp_docs: Path):
    write_file(tmp_docs / "high-cpu-usage.md", "# Title")
    rules = [AlertRule(alert="HighCPUUsage", runbook_url=None, group="g")]
    findings = check_runbooks(
        rules, docs_root=tmp_docs, base_url="https://docs.example.test/runbooks"
    )
    assert findings == [
        Finding(
            alert="HighCPUUsage",
            status="missing",
            suggestion="https://docs.example.test/runbooks/high-cpu-usage.md",
            detail="no runbook_url annotation",
        )
    ]


def test_missing_with_base_url_no_file(tmp_docs: Path):
    rules = [AlertRule(alert="HighCPUUsage", runbook_url=None, group="g")]
    findings = check_runbooks(
        rules, docs_root=tmp_docs, base_url="https://docs.example.test/runbooks"
    )
    assert findings[0].status == "missing"
    assert findings[0].suggestion is None


def test_missing_without_base_url_file_exists(tmp_docs: Path):
    write_file(tmp_docs / "high-cpu-usage.md", "# T")
    rules = [AlertRule(alert="HighCPUUsage", runbook_url=None, group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].suggestion == "high-cpu-usage.md"


def test_templated_url(tmp_docs: Path):
    rules = [AlertRule(alert="A", runbook_url="{{ $labels.job }}", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "templated"


def test_invalid_url_schemes(tmp_docs: Path):
    for url in ["javascript:alert(1)", "ftp://example.com/x"]:
        rules = [AlertRule(alert="A", runbook_url=url, group="g")]
        findings = check_runbooks(rules, docs_root=tmp_docs)
        assert findings[0].status == "invalid_url"


def test_local_relative_ok_no_fragment(tmp_docs: Path):
    write_file(tmp_docs / "foo.md", "# T")
    rules = [AlertRule(alert="A", runbook_url="foo.md", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "ok"


def test_local_relative_anchor_ok(tmp_docs: Path):
    write_file(tmp_docs / "foo.md", "## Section")
    rules = [AlertRule(alert="A", runbook_url="foo.md#section", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "ok"


def test_local_anchor_missing(tmp_docs: Path):
    write_file(tmp_docs / "foo.md", "## Other")
    rules = [AlertRule(alert="A", runbook_url="foo.md#missing", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "anchor_missing"


def test_local_file_missing(tmp_docs: Path):
    rules = [AlertRule(alert="A", runbook_url="nope.md", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "broken"


def test_base_url_mapping_ok(tmp_docs: Path):
    write_file(tmp_docs / "db.md", "## Replication Lag")
    url = "https://docs.example.test/runbooks/db.md#replication-lag"
    rules = [AlertRule(alert="A", runbook_url=url, group="g")]
    findings = check_runbooks(
        rules, docs_root=tmp_docs, base_url="https://docs.example.test/runbooks"
    )
    assert findings[0].status == "ok"


def test_base_url_mapping_anchor_missing(tmp_docs: Path):
    write_file(tmp_docs / "db.md", "## Other")
    url = "https://docs.example.test/runbooks/db.md#replication-lag"
    rules = [AlertRule(alert="A", runbook_url=url, group="g")]
    findings = check_runbooks(
        rules, docs_root=tmp_docs, base_url="https://docs.example.test/runbooks"
    )
    assert findings[0].status == "anchor_missing"


def test_base_url_mapping_broken(tmp_docs: Path):
    url = "https://docs.example.test/runbooks/nope.md#x"
    rules = [AlertRule(alert="A", runbook_url=url, group="g")]
    findings = check_runbooks(
        rules, docs_root=tmp_docs, base_url="https://docs.example.test/runbooks"
    )
    assert findings[0].status == "broken"


def test_base_url_with_trailing_slash_normalized(tmp_docs: Path):
    write_file(tmp_docs / "foo.md", "# T")
    url = "https://docs.example.test/runbooks/foo.md"
    rules = [AlertRule(alert="A", runbook_url=url, group="g")]
    findings = check_runbooks(
        rules, docs_root=tmp_docs, base_url="https://docs.example.test/runbooks/"
    )
    assert findings[0].status == "ok"


def test_outside_root_relative(tmp_docs: Path):
    rules = [AlertRule(alert="A", runbook_url="../../etc/passwd", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "outside_root"


def test_outside_root_base_url(tmp_docs: Path):
    url = "https://docs.example.test/runbooks/../secrets.md"
    rules = [AlertRule(alert="A", runbook_url=url, group="g")]
    findings = check_runbooks(
        rules, docs_root=tmp_docs, base_url="https://docs.example.test/runbooks"
    )
    assert findings[0].status == "outside_root"


@pytest.mark.skipif(os.name == "nt", reason="symlinks often require privileges on Windows")
def test_symlink_outside_root(tmp_docs: Path, tmp_path: Path):
    outside = tmp_path / "outside.md"
    write_file(outside, "secret")
    link = tmp_docs / "link.md"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation not allowed")
    rules = [AlertRule(alert="A", runbook_url="link.md", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "outside_root"


def test_external_unchecked(tmp_docs: Path):
    rules = [AlertRule(alert="A", runbook_url="https://wiki.example.test/x", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "unchecked"


def test_external_http_check_ok(tmp_docs: Path):
    rules = [AlertRule(alert="A", runbook_url="https://wiki.example.test/x", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs, http_check=lambda url: 200)
    assert findings[0].status == "ok"


def test_external_http_check_broken(tmp_docs: Path):
    rules = [AlertRule(alert="A", runbook_url="https://wiki.example.test/x", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs, http_check=lambda url: 404)
    assert findings[0].status == "broken"


def test_external_http_check_exception(tmp_docs: Path):
    def boom(url: str) -> int:
        raise RuntimeError("network down")

    rules = [AlertRule(alert="A", runbook_url="https://wiki.example.test/x", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs, http_check=boom)
    assert findings[0].status == "broken"
    assert findings[0].detail == "check failed"


def test_query_string_ignored_for_local_file(tmp_docs: Path):
    write_file(tmp_docs / "foo.md", "# T")
    rules = [AlertRule(alert="A", runbook_url="foo.md?x=1", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "ok"


def test_percent_decoding(tmp_docs: Path):
    write_file(tmp_docs / "a b.md", "# T")
    rules = [AlertRule(alert="A", runbook_url="a%20b.md", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "ok"


def test_malformed_url_is_invalid_not_crash(tmp_docs: Path):
    rules = [AlertRule(alert="A", runbook_url="https://[runbooks/x.md", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "invalid_url"


def test_null_byte_local_path_outside_root(tmp_docs: Path):
    rules = [AlertRule(alert="A", runbook_url="foo%00.md", group="g")]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert findings[0].status == "outside_root"


def test_sort_by_group_then_alert(tmp_docs: Path):
    rules = [
        AlertRule(alert="B", runbook_url=None, group="g2"),
        AlertRule(alert="A", runbook_url=None, group="g1"),
        AlertRule(alert="C", runbook_url=None, group="g1"),
    ]
    findings = check_runbooks(rules, docs_root=tmp_docs)
    assert [f.alert for f in findings] == ["A", "C", "B"]


# ---------- main CLI ----------


def test_main_all_ok(capsys, tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    write_file(docs / "high-cpu-usage.md", "# T")
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text(
        """
groups:
- name: g
  rules:
  - alert: HighCPUUsage
    expr: up==0
    annotations:
      runbook_url: high-cpu-usage.md
""",
        encoding="utf-8",
    )
    rc = main(["check", str(rules_file), "--docs", str(docs)])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == ""
    assert captured.err == ""


def test_main_non_ok_prints_and_returns_1(capsys, tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text(
        """
groups:
- name: g
  rules:
  - alert: HighCPUUsage
    expr: up==0
""",
        encoding="utf-8",
    )
    rc = main(["check", str(rules_file), "--docs", str(docs)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "HighCPUUsage\tmissing\t" in captured.out


def test_module_entry_point_runs(monkeypatch):
    import runpy

    monkeypatch.setattr("sys.argv", ["runbook-linker", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("runbook_linker", run_name="__main__", alter_sys=True)
    assert exc_info.value.code == 0


def test_main_unreadable_file_returns_2(capsys, tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    rc = main(["check", str(tmp_path / "missing.yml"), "--docs", str(docs)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "error:" in captured.err


def test_main_base_url_prints_one_line_per_non_ok(capsys, tmp_path: Path):
    # Non-ok findings print one line each in the form '<alert>\t<status>\t<detail>'.
    docs = tmp_path / "docs"
    docs.mkdir()
    write_file(docs / "high-cpu-usage.md", "# High CPU Usage")
    write_file(docs / "db.md", "## Replication Lag")
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text(
        """
groups:
- name: g
  rules:
  - alert: HighCPUUsage
    expr: up==0
  - alert: DBLag
    expr: up==0
    annotations:
      runbook_url: https://docs.example.test/runbooks/db.md#replication-lag
""",
        encoding="utf-8",
    )
    rc = main(
        [
            "check",
            str(rules_file),
            "--docs",
            str(docs),
            "--base-url",
            "https://docs.example.test/runbooks",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 1
    lines = captured.out.splitlines()
    assert len(lines) == 1
    alert, status, detail = lines[0].split("\t")
    assert (alert, status, detail) == ("HighCPUUsage", "missing", "no runbook_url annotation")
    line_format = r"<alert>\t<status>\t<detail>"
    assert line_format == "<alert>\\t<status>\\t<detail>"
