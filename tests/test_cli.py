"""The `rampart` CLI: exit codes, refusals, config precedence, output hygiene.

Driven in-process through ``rampart.cli.main([...])`` with throwaway work dirs. Only a few tests
touch the demo target (vuln_server); most exercise the refusal / validation paths, which never
send a request.
"""

from __future__ import annotations

import json
import os
import shlex
import socket

import pytest
from conftest import PLATFORM, write_engagement

from rampart import cli

DEMO_SRC = os.path.join(PLATFORM, "examples", "demo_target", "src")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run(argv, capsys):
    rc = cli.main(argv)
    out = capsys.readouterr()
    return rc, out.out + out.err


@pytest.fixture
def scope(tmp_path):
    return write_engagement(tmp_path, 18123)


# ------------------------------------------------------------------ scope gate (#1)
@pytest.mark.parametrize(
    "target,needle",
    [
        ("http://127.0.0.1:18124", "port 18124 is not authorized"),
        ("127.0.0.1:18123", "scheme"),
        ("not a url", "scheme"),
        ("http://127.0.0.1:99999", "invalid port"),
        ("http://10.9.9.9:18123", "not in the rampart.scope.yaml scope"),
    ],
)
def test_test_refuses_bad_targets(tmp_path, scope, capsys, target, needle):
    work = tmp_path / "w"
    rc, out = _run(["test", "--scope-file", scope, "--target", target, "--work-dir", str(work)], capsys)
    assert rc == 2 and needle in out
    assert not work.exists()


def test_llm_test_refuses_out_of_scope_port(tmp_path, scope, capsys):
    rc, out = _run(
        [
            "llm-test",
            "--scope-file",
            scope,
            "--target",
            "http://127.0.0.1:18124",
            "--work-dir",
            str(tmp_path / "w"),
        ],
        capsys,
    )
    assert rc == 2 and "port 18124" in out


# ------------------------------------------------------------------ unreachable (#7)
def test_unreachable_target_exits_2_even_with_ci(tmp_path, capsys):
    port = _free_port()
    scope_file = write_engagement(tmp_path, port)
    work = tmp_path / "w"
    rc, out = _run(
        [
            "test",
            "--scope-file",
            scope_file,
            "--target",
            f"http://127.0.0.1:{port}",
            "--work-dir",
            str(work),
            "--ci",
            "--fail-on",
            "low",
        ],
        capsys,
    )
    assert rc == 2 and "target unreachable" in out
    scan = json.load(open(work / "scan.json", encoding="utf-8"))
    assert scan["status"] == "incomplete"


def test_llm_test_unreachable_exits_2(tmp_path, capsys):
    port = _free_port()
    scope_file = write_engagement(tmp_path, port)
    rc, out = _run(
        [
            "llm-test",
            "--scope-file",
            scope_file,
            "--target",
            f"http://127.0.0.1:{port}",
            "--work-dir",
            str(tmp_path / "w"),
        ],
        capsys,
    )
    assert rc == 2 and "INCOMPLETE" in out
    assert "error" in out  # per-probe outcome shown


def test_kill_file_denials_are_reported_and_fail_the_run(tmp_path, capsys):
    port = _free_port()
    scope_file = write_engagement(tmp_path, port)
    work = tmp_path / "w"
    work.mkdir()
    (work / "KILL").write_text("stop", encoding="utf-8")
    rc, out = _run(
        ["test", "--scope-file", scope_file, "--target", f"http://127.0.0.1:{port}", "--work-dir", str(work)],
        capsys,
    )
    assert rc == 2 and "kill switch engaged" in out
    assert "budget denied" in out and "kill_switch=" in out
    scan = json.load(open(work / "scan.json", encoding="utf-8"))
    assert scan["budget"]["denied"]["kill_switch"] >= 1 and scan["budget"]["denied_total"] >= 1


def test_grpc_mode_accepts_grpc_scheme(tmp_path, capsys, monkeypatch):
    from rampart import grpc_scan

    monkeypatch.setattr(grpc_scan, "available", lambda: False)
    port = _free_port()
    scope_file = write_engagement(tmp_path, port)
    rc, out = _run(
        [
            "grpc",
            "--scope-file",
            scope_file,
            "--target",
            f"grpc://127.0.0.1:{port}",
            "--work-dir",
            str(tmp_path / "w"),
        ],
        capsys,
    )
    assert rc == 0, out
    assert "grpc: skipped" in out
    rc, out = _run(
        [
            "dast",
            "--scope-file",
            scope_file,
            "--target",
            f"grpc://127.0.0.1:{port}",
            "--work-dir",
            str(tmp_path / "w2"),
        ],
        capsys,
    )
    assert rc == 2 and "scheme" in out


# ------------------------------------------------------------------ white-box (#14)
def test_sast_offline_without_target(tmp_path, scope, capsys):
    work = tmp_path / "w"
    rc, out = _run(
        ["sast", "--repo", DEMO_SRC, "--scope-file", scope, "--work-dir", str(work), "--ci"], capsys
    )
    assert rc == 0, out
    assert "white-box only" in out and "native SAST" in out
    assert "do not gate unless --fail-on-static" in out
    assert "static exposure" in out  # static line in the summary (#15)
    report = json.load(open(work / "reports" / "report.json", encoding="utf-8"))
    assert any("sast" in f["tags"] for f in report["findings"])
    scan = json.load(open(work / "scan.json", encoding="utf-8"))
    assert scan["offline"] and scan["requests"]["executed"] == 0


def test_sast_with_target_validates_it_but_never_contacts_it(tmp_path, scope, capsys):
    work = tmp_path / "w"
    base = ["sast", "--repo", DEMO_SRC, "--scope-file", scope, "--work-dir", str(work)]
    rc, out = _run(base + ["--target", "http://127.0.0.1:18124"], capsys)
    assert rc == 2 and "port 18124" in out  # still scope-checked
    rc, out = _run(base + ["--target", "http://127.0.0.1:18123", "--crawl"], capsys)
    assert rc == 0, out
    scan = json.load(open(work / "scan.json", encoding="utf-8"))
    assert scan["offline"] and scan["requests"]["executed"] == 0 and scan["budget"]["requests_used"] == 0


def test_fail_on_static_gates(tmp_path, scope, capsys):
    rc, out = _run(
        [
            "sast",
            "--repo",
            DEMO_SRC,
            "--scope-file",
            scope,
            "--work-dir",
            str(tmp_path / "w"),
            "--fail-on-static",
            "HIGH",
        ],
        capsys,
    )
    assert rc == 1 and "static gate failed" in out


def test_repo_must_exist(tmp_path, scope, capsys):
    rc, out = _run(
        ["sast", "--repo", str(tmp_path / "nope"), "--scope-file", scope, "--work-dir", str(tmp_path / "w")],
        capsys,
    )
    assert rc == 2 and "--repo" in out


def test_sast_without_repo_or_target_is_refused(tmp_path, scope, capsys):
    rc, out = _run(["sast", "--scope-file", scope, "--work-dir", str(tmp_path / "w")], capsys)
    assert rc == 2 and "--repo" in out


def test_test_without_target_is_refused(tmp_path, scope, capsys):
    rc, out = _run(["test", "--scope-file", scope, "--work-dir", str(tmp_path / "w")], capsys)
    assert rc == 2 and "no target" in out


# ------------------------------------------------------------------ input validation (#10/#17/#19)
def test_fail_on_choices_case_insensitive(tmp_path, scope):
    p = cli.build_parser()
    assert p.parse_args(["test", "--fail-on", "HIGH"]).fail_on == "high"
    with pytest.raises(SystemExit) as e:
        p.parse_args(["test", "--fail-on", "severe"])
    assert e.value.code == 2
    with pytest.raises(SystemExit):
        p.parse_args(["pr-comment", "--fail-on", "bogus"])


def test_unknown_report_format_exits_2(tmp_path, scope, capsys):
    rc, out = _run(
        [
            "test",
            "--scope-file",
            scope,
            "--target",
            "http://127.0.0.1:18123",
            "--work-dir",
            str(tmp_path / "w"),
            "--report",
            "html,pdf",
        ],
        capsys,
    )
    assert rc == 2 and "unknown report format 'pdf'" in out and "sarif" in out


def test_malformed_openapi_and_unknown_intel_exit_2(tmp_path, scope, capsys):
    (tmp_path / "bad.json").write_text("{nope", encoding="utf-8")
    base = [
        "test",
        "--scope-file",
        scope,
        "--target",
        "http://127.0.0.1:18123",
        "--work-dir",
        str(tmp_path / "w"),
    ]
    rc, out = _run(base + ["--openapi", str(tmp_path / "bad.json")], capsys)
    assert rc == 2 and "malformed JSON" in out and "Traceback" not in out
    rc, out = _run(base + ["--intel", "gpt-banana"], capsys)
    assert rc == 2 and "unknown intelligence provider" in out


def test_corrupt_audit_log_exits_2(tmp_path, scope, capsys):
    work = tmp_path / "w"
    work.mkdir()
    (work / "audit.jsonl").write_text("{garbage\n", encoding="utf-8")
    rc, out = _run(
        ["test", "--scope-file", scope, "--target", "http://127.0.0.1:18123", "--work-dir", str(work)], capsys
    )
    assert rc == 2 and "audit log problem" in out


# ------------------------------------------------------------------ config precedence (#16)
def test_config_precedence(tmp_path, scope):
    cfg = tmp_path / "rampart.yaml"
    cfg.write_text(
        "work-dir: from-config\nreport: [json, sarif]\nfail_on: medium\nci: true\nparallel: 3\n"
        f"scope-file: {scope}\ncrawl: true\niac: true\nintel: deterministic\n",
        encoding="utf-8",
    )
    p = cli.build_parser()
    sub = p._rampart_subparsers["test"]
    args = p.parse_args(["test", "--config", str(cfg), "--report", "html", "--parallel", "5"])
    cli._apply_config(args, sub)
    assert args.report == "html" and args.parallel == 5  # CLI wins
    assert args.work_dir == "from-config" and args.fail_on == "medium" and args.ci is True  # config wins
    assert args.scope_file == scope and args.crawl is True and args.do_iac is True
    assert args.application == "target" and args.login_path == "/api/login"  # built-in defaults
    # without a config, the built-in defaults apply
    args2 = p.parse_args(["test"])
    cli._apply_config(args2, sub)
    assert (
        args2.work_dir == ".rampart" and args2.fail_on == "high" and args2.ci is False and args2.parallel == 0
    )


def test_bad_config_value_exits_2(tmp_path, scope, capsys):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("parallel: lots\n", encoding="utf-8")
    rc, out = _run(
        ["test", "--config", str(cfg), "--scope-file", scope, "--target", "http://127.0.0.1:18123"], capsys
    )
    assert rc == 2 and "parallel" in out
    rc, out = _run(["test", "--config", str(tmp_path / "missing.yaml")], capsys)
    assert rc == 2 and "config file not found" in out
    cfg.write_text("fail-on: severe\n", encoding="utf-8")
    rc, out = _run(
        ["test", "--config", str(cfg), "--scope-file", scope, "--target", "http://127.0.0.1:18123"], capsys
    )
    assert rc == 2 and "--fail-on" in out


# ------------------------------------------------------------------ pipeline (#5)
def test_pipeline_is_read_only_unless_active(tmp_path, scope, capsys, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "_build_engagement", lambda cfg: (seen.append(cfg), (None, "stop"))[1])
    rc, out = _run(["pipeline", "--scope-file", scope, "--target", "http://127.0.0.1:18123"], capsys)
    assert rc == 2 and seen[0].active is False and seen[0].infra is True and seen[0].crawl is True
    assert "add --active" in out
    rc, out = _run(
        [
            "pipeline",
            "--scope-file",
            scope,
            "--target",
            "http://127.0.0.1:18123",
            "--active",
            "--approve-tier2",
        ],
        capsys,
    )
    assert seen[1].active is True and "--active: gated WRITE" in out and "AUTO-APPROVED" in out


def test_test_with_repo_enables_whitebox_and_sca_online_implies_sca(tmp_path, scope, capsys, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "_build_engagement", lambda cfg: (seen.append(cfg), (None, "stop"))[1])
    _run(["test", "--scope-file", scope, "--target", "http://127.0.0.1:18123", "--repo", DEMO_SRC], capsys)
    assert seen[0].do_sast and seen[0].do_sca and not seen[0].do_iac
    _run(
        [
            "dast",
            "--scope-file",
            scope,
            "--target",
            "http://127.0.0.1:18123",
            "--sca-online",
            "--oob-collaborator-url",
            "http://oob.example.test:9",
        ],
        capsys,
    )
    assert seen[1].do_sca and seen[1].oob_collaborator_url == "http://oob.example.test:9"


# ------------------------------------------------------------------ report / verify-audit (#18)
def test_report_without_stored_run_exits_2_and_creates_nothing(tmp_path, scope, capsys):
    work = tmp_path / "empty-run"
    rc, out = _run(["report", "--scope-file", scope, "--work-dir", str(work)], capsys)
    assert rc == 2 and "no stored run" in out and not work.exists()


def test_report_reads_target_from_stored_run(tmp_path, scope, capsys):
    work = tmp_path / "run"
    work.mkdir()
    (work / "scan.json").write_text(json.dumps({"target": "http://127.0.0.1:18123"}), encoding="utf-8")
    (work / "findings.json").write_text("[]", encoding="utf-8")
    rc, out = _run(
        ["report", "--scope-file", scope, "--work-dir", str(work), "--format", "JSON,Html"], capsys
    )
    assert rc == 0, out
    assert "target (from stored run)" in out and (work / "reports" / "report.json").exists()
    rc, out = _run(["report", "--scope-file", scope, "--work-dir", str(work), "--format", "docx"], capsys)
    assert rc == 2 and "valid:" in out


def test_verify_audit_empty_and_missing(tmp_path, capsys):
    rc, out = _run(["verify-audit", "--work-dir", str(tmp_path / "none")], capsys)
    assert rc == 2 and "no events" in out
    (tmp_path / "w").mkdir()
    (tmp_path / "w" / "audit.jsonl").write_text("", encoding="utf-8")
    rc, out = _run(["verify-audit", "--work-dir", str(tmp_path / "w")], capsys)
    assert rc == 1 and "no events" in out


# ------------------------------------------------------------------ pr-comment (#9/#10/#19)
def _report_json(path, findings):
    path.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(path)


def test_pr_comment_gate_and_malformed(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    rc, out = _run(["pr-comment", "--report", str(bad), "--dry-run"], capsys)
    assert rc == 2 and "could not read" in out
    fixed = {"title": "a", "severity": "critical", "state": "Fixed", "verification": {"validated": True}}
    rep = _report_json(tmp_path / "r.json", [fixed])
    rc, _ = _run(["pr-comment", "--report", rep, "--dry-run", "--fail-on", "High"], capsys)
    assert rc == 0  # a Fixed finding is not confirmed
    open_f = {"title": "b", "severity": "HIGH", "state": "Validated", "verification": {"validated": True}}
    rep = _report_json(tmp_path / "r2.json", [open_f])
    rc, _ = _run(["pr-comment", "--report", rep, "--dry-run", "--fail-on", "high"], capsys)
    assert rc == 1


def test_ci_gate_uses_shared_confirmed_rule():
    from types import SimpleNamespace

    from rampart.schemas.finding import Finding, State, Verification

    def f(sev, state):
        return Finding(
            engagement_id="T",
            title="t",
            vuln_class="SQLI",
            severity=sev,
            confidence="confirmed",
            state=state,
            verification=Verification(validated=True),
        )

    assert cli._ci_gate(SimpleNamespace(findings=[f("critical", State.FIXED)]), "low") == ""
    assert cli._ci_gate(SimpleNamespace(findings=[f("weird", State.VALIDATED)]), "low") == ""  # info
    assert cli._ci_gate(SimpleNamespace(findings=[f("HIGH", State.VALIDATED)]), "high")


# ------------------------------------------------------------------ output hygiene (#20)
def test_clean_strips_ansi_and_control_chars():
    s = cli._clean("evil\x1b[2J\x1b]0;pwned\x07title\r\nnext\x9b31m\x00")
    assert "\x1b" not in s and "\x07" not in s and "\r" not in s and "\x00" not in s and "\x9b" not in s
    assert "evil" in s and "title" in s and "next" in s


# ------------------------------------------------------------------ serve (#21)
def test_serve_port_in_use_exits_1(tmp_path, capsys, monkeypatch):
    import rampart.server.dashboard as dash

    def boom(*a, **k):
        raise OSError(98, "cannot bind the Rampart dashboard: the port is already in use")

    monkeypatch.setattr(dash, "build_server", boom)
    rc, out = _run(["serve", "--port", "19097", "--work-dir", str(tmp_path / "w")], capsys)
    assert rc == 1 and "already in use" in out and "dashboard on" not in out


# ------------------------------------------------------------------ tools / features / help (#22)
def test_tools_points_to_docs(capsys):
    rc, out = _run(["tools"], capsys)
    assert rc == 0 and "docs/EXTERNAL_TOOLS.md" in out and "reports/" not in out and "gRPC" in out


def test_features_examples_parse_and_count_is_real(capsys):
    from rampart.validation.registry import ORACLES

    rc, out = _run(["features"], capsys)
    assert rc == 0 and f"{len(ORACLES)} oracle-validated classes" in out and "16 oracle" not in out
    p = cli.build_parser()
    examples = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("rampart ")]
    assert len(examples) >= 15
    for ex in examples:
        argv = shlex.split(ex)[1:]
        args = p.parse_args(argv)  # must not SystemExit (e.g. "--target required")
        if args.cmd in cli._MODES and args.cmd not in ("sast", "sca", "iac"):
            assert args.target, ex
        if args.cmd in ("pipeline", "llm-test"):
            assert args.target, ex


def test_no_subcommand_prints_help_exit_2(capsys):
    rc, out = _run([], capsys)
    assert rc == 2 and "usage:" in out


# ------------------------------------------------------------------ live demo: retest exit codes (#11)
def test_retest_exit_codes(tmp_path, vuln_server, capsys):
    scope_file = write_engagement(tmp_path, vuln_server.port)
    work = tmp_path / "run"
    rc, out = _run(
        [
            "test",
            "--scope-file",
            scope_file,
            "--target",
            vuln_server.base_url,
            "--work-dir",
            str(work),
            "--openapi",
            str(tmp_path / "openapi.json"),
            "--appmodel-seed",
            str(tmp_path / "seed.json"),
            "--report",
            "json",
        ],
        capsys,
    )
    assert rc == 0, out
    # retest without --target replays against the stored target: still vulnerable -> exit 1
    rc, out = _run(
        ["retest", "--scope-file", scope_file, "--work-dir", str(work), "--report", "json"], capsys
    )
    assert rc == 1, out
    assert "target (from stored run)" in out and "still-vulnerable" in out and "not retestable" in out
    # the target goes away -> inconclusive (never a traceback) -> exit 2
    down = _free_port()
    down_dir = tmp_path / "down"
    down_dir.mkdir()
    down_scope = write_engagement(down_dir, down)
    rc, out = _run(
        [
            "retest",
            "--scope-file",
            down_scope,
            "--target",
            f"http://127.0.0.1:{down}",
            "--work-dir",
            str(work),
        ],
        capsys,
    )
    assert rc == 2 and "inconclusive" in out and "Traceback" not in out
