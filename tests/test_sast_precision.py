"""SAST precision/recall regressions: structural (not ast.dump-text) sink matching, import-alias
resolution, YAML loader semantics, string-built SQL tracking, crash-safety on pathological input,
BOM / PEP 263 sources, secret-pattern coverage, and diff-aware (--since) file selection."""

import os
import shutil
import subprocess

import pytest

from rampart.sast import scan_dependencies, scan_secrets, scan_source
from rampart.sast import scanner as sast_scanner
from rampart.sast import secrets as sast_secrets
from rampart.sast.scanner import changed_py_files, changed_py_files_status

SINKS = """\
import os
import subprocess
import pickle
import yaml
from subprocess import run, Popen
from os import system
import pickle as pk
from yaml import load as yload


def vuln_fstring(cursor, uid):
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")


def vuln_var(cursor, uid):
    q = f"SELECT * FROM users WHERE id = {uid}"
    cursor.execute(q)


def safe_param(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))


def safe_builder(cursor, builder):
    cursor.execute(builder.compile_sql())


def safe_const_concat(cursor):
    cursor.execute("SELECT * " + "FROM users")


def not_sql(self, call, ip):
    return self.executor.execute(call, ip)


def sh_fromimport(user):
    run("ls " + user, shell=True)


def sh_popen(user):
    Popen(f"cat {user}", shell=True)


def os_system_from(user):
    system("ls " + user)


def pk2(blob):
    pk.loads(blob)


def y_fullloader(s):
    yaml.load(s, Loader=yaml.Loader)


def y_unsafe_load(s):
    yaml.unsafe_load(s)


def y_safe_kw(s):
    yaml.load(s, Loader=yaml.SafeLoader)


def y_safe_pos(s):
    yaml.load(s, yaml.SafeLoader)


def y_from(s):
    yload(s)


def openjoin(name, path, args):
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "data.json")) as fh:
        fh.read()
    with open(name) as fh:
        fh.read()
    with open(path + ".bak") as fh:
        return fh.read()


def open_from_request(request):
    return open("/srv/files/" + request.args["f"]).read()


def shell_const():
    subprocess.run("ls -la", shell=True)
"""


def test_sql_and_path_hints_are_structural_not_dump_text(tmp_path):
    (tmp_path / "app.py").write_text(SINKS, encoding="utf-8")
    findings = scan_source(str(tmp_path))
    lines = SINKS.splitlines()
    # SQLi: the f-string AND the `q = f"..."; cursor.execute(q)` form — not the parameterised,
    # builder, constant-concatenation or non-DB `executor.execute(call)` calls.
    sqli = {f.affected_code.start_line for f in findings if f.cwe == ["CWE-89"]}
    assert sqli == {
        lines.index('    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")') + 1,
        lines.index("    cursor.execute(q)") + 1,
    }
    # open(): only the request-derived path, never os.path.join(const)/a plain `name`/`path` param
    cwe22 = [f for f in findings if f.cwe == ["CWE-22"]]
    assert [lines[f.affected_code.start_line - 1].strip() for f in cwe22] == [
        'return open("/srv/files/" + request.args["f"]).read()'
    ]


def test_import_aliases_and_yaml_loader_semantics(tmp_path):
    (tmp_path / "app.py").write_text(SINKS, encoding="utf-8")
    lines = SINKS.splitlines()
    got = {(lines[f.affected_code.start_line - 1].strip(), f.cwe[0]) for f in scan_source(str(tmp_path))}
    for expected in (
        ('run("ls " + user, shell=True)', "CWE-78"),
        ('Popen(f"cat {user}", shell=True)', "CWE-78"),
        ('system("ls " + user)', "CWE-78"),
        ("pk.loads(blob)", "CWE-502"),
        ("yaml.load(s, Loader=yaml.Loader)", "CWE-502"),
        ("yaml.unsafe_load(s)", "CWE-502"),
        ("yload(s)", "CWE-502"),
    ):
        assert expected in got, expected
    for safe in (
        "yaml.load(s, Loader=yaml.SafeLoader)",
        "yaml.load(s, yaml.SafeLoader)",
        'subprocess.run("ls -la", shell=True)',
        'cursor.execute("SELECT * " + "FROM users")',
        "cursor.execute(builder.compile_sql())",
        "return self.executor.execute(call, ip)",
    ):
        assert not any(line == safe for line, _ in got), safe


def test_deeply_nested_source_does_not_crash_the_scan(tmp_path):
    (tmp_path / "gen.py").write_text("MSG = " + " + ".join(f'"s{i}"' for i in range(3000)) + "\n")
    (tmp_path / "deep.py").write_text("x = " + "[" * 150 + "]" * 150 + "\n")
    (tmp_path / "ok.py").write_text("import os\n\ndef f(u):\n    os.system('ls ' + u)\n")
    findings = scan_source(str(tmp_path))  # must not raise RecursionError
    assert [f.affected_code.file for f in findings] == ["ok.py"]


def test_bom_and_pep263_latin1_sources_are_scanned(tmp_path):
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfimport os\ndef f(u):\n    os.system('ls ' + u)\n")
    (tmp_path / "latin1.py").write_bytes(
        b"# -*- coding: latin-1 -*-\nimport os\nNAME = 'caf\xe9'\ndef f(u):\n    os.system('ls ' + u)\n"
    )
    got = sorted((f.affected_code.file, f.affected_code.start_line) for f in scan_source(str(tmp_path)))
    assert got == [("bom.py", 3), ("latin1.py", 5)]


def test_inline_suppression_and_file_cap_note(tmp_path):
    (tmp_path / "a.py").write_text("import os\n\ndef f(u):\n    os.system(u)  # nosec\n")
    (tmp_path / "b.py").write_text("import os\n\ndef f(u):\n    os.system(u)\n")
    assert [f.affected_code.file for f in scan_source(str(tmp_path))] == ["b.py"]
    scan_source(str(tmp_path), max_files=1)
    assert any("cap" in n for n in sast_scanner.last_scan_notes)


# ----------------------------------------------------------------------------------- secrets
def test_secret_patterns_cover_prefixed_names_and_unquoted_config(tmp_path):
    # Fixture secrets are written with "@" for the quote character (swapped in at runtime) so this
    # test file itself does not trip Rampart's own secret scan.
    (tmp_path / "settings.py").write_text(
        (
            "SECRET_KEY = @django-insecure-9x!k2@q#zv8w^p0r7t6y5u4i3o2@\n"
            "DB_PASSWORD = @Pr0dDbPassw0rd99@\n"
            "client_secret = @a8f5f167f44f4964e6c998dee827110c@\n"
            "STRIPE_API_KEY = @rk_live_51HxQwErTyUiOpAsDf@\n"
            "password = @latestRelease2024@\n"
        )
        .replace("@", '"')
        .replace('9x!k2"q', "9x!k2@q")
        + 'password_from_env = os.environ["DB_PASSWORD"]\n'
    )
    (tmp_path / ".env").write_text("DB_PASSWORD=Hunter2Hunter2\nDEBUG=true\n")
    (tmp_path / "Dockerfile").write_text("FROM x:1\nENV DB_PASSWORD=supersecret123\n")
    (tmp_path / "settings.ini").write_text("[db]\npassword = S3cr3tPassw0rd!\n")
    (tmp_path / "placeholder.yaml").write_text(
        'db:\n  password: "changeme"\n  api_key: "${API_KEY}"\n  secret: "<your-secret>"\n'
    )
    (tmp_path / "aws_doc.py").write_text('AWS_KEY = "AKIA' + 'IOSFODNN7EXAMPLE"\n')
    got = sorted((f.affected_code.file, f.affected_code.start_line) for f in scan_secrets(str(tmp_path)))
    assert got == [
        (".env", 1),
        ("Dockerfile", 2),
        ("settings.ini", 2),
        ("settings.py", 1),
        ("settings.py", 2),
        ("settings.py", 3),
        ("settings.py", 4),
        ("settings.py", 5),  # "latestRelease2024" is not a placeholder just because it contains "test"
    ]


def test_secret_scan_skips_binaries_and_unknown_extensions(tmp_path):
    key = "AKIA" + "Q3EGRTYUIOPASDFG"
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00" + key.encode() + b"\x00" * 50)
    (tmp_path / "blob").write_bytes(b"\x00\x01" + key.encode())
    (tmp_path / "notes.bin").write_text(key)
    (tmp_path / "aws.py").write_text(f'AWS_KEY = "{key}"\n')
    assert [f.affected_code.file for f in scan_secrets(str(tmp_path))] == ["aws.py"]
    scan_secrets(str(tmp_path), max_files=0)
    assert any("cap" in n for n in sast_secrets.last_scan_notes)


def test_dependency_inventory_treats_ranges_and_wildcards_as_unpinned(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==0.12.2\nurllib3>=1.24,<2\nidna==2.*\nPyYAML\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest>=7\n")
    findings = scan_dependencies(str(tmp_path))
    by_file = {f.affected_code.file: f for f in findings}
    assert set(by_file) == {"requirements.txt", "requirements-dev.txt"}
    desc = by_file["requirements.txt"].description
    assert "urllib3" in desc and "idna" in desc and "pyyaml" in desc and "flask" not in desc
    assert by_file["requirements.txt"].title.endswith("(3)")


# ---------------------------------------------------------------------------------- --since
def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_since_paths_are_relative_to_subdir_and_include_uncommitted(tmp_path):
    repo = tmp_path / "my repo"
    svc = repo / "svc" / "sub dir"
    svc.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "svc" / "old.py").write_text("x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "one")
    (repo / "svc" / "café.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    (svc / "spaced file.py").write_text("y = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "two")
    (repo / "svc" / "old.py").write_text("x = 2\n")  # uncommitted edit
    (repo / "svc" / "untracked.py").write_text("z = 3\n")  # untracked file

    files, status = changed_py_files_status(str(repo / "svc"), "HEAD~1")
    assert status == "ok"
    assert files == {"café.py", "sub dir/spaced file.py", "old.py", "untracked.py"}
    only = changed_py_files(str(repo / "svc"), "HEAD~1")
    assert [f.affected_code.file for f in scan_source(str(repo / "svc"), only_files=only)] == ["café.py"]

    assert changed_py_files(str(repo / "svc"), "no-such-ref") is None
    assert changed_py_files.last_status == "invalid-ref"
    assert changed_py_files_status(str(tmp_path / "nogit"), "HEAD")[1] == "not-a-git-repo"


def test_demo_target_findings_unchanged():
    demo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples", "demo_target"))
    got = sorted((f.affected_code.start_line, f.cwe[0]) for f in scan_source(os.path.join(demo, "src")))
    assert got == [
        (19, "CWE-78"),
        (23, "CWE-78"),
        (27, "CWE-89"),
        (32, "CWE-918"),
        (36, "CWE-502"),
        (40, "CWE-95"),
        (44, "CWE-327"),
        (48, "CWE-22"),
        (55, "CWE-489"),
    ]
