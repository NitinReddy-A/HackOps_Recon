"""Native IaC / cloud-config scanner: Terraform, CloudFormation, Kubernetes, Dockerfile.

These are STATIC findings (never runtime-validated); they are correlated with DAST findings
by CWE the same way SAST hits are.
"""

import os

from rampart.iac import scan_iac

IAC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples", "demo_target", "iac"))


def test_iac_finds_expected_cwes():
    findings = scan_iac(IAC, "x")
    cwes = {c for f in findings for c in f.cwe}
    # open SG + public S3 (CWE-284), wildcard IAM (CWE-269), privileged pod (CWE-250),
    # :latest image tag (CWE-1104), curl|sh remote pipe (CWE-494)
    for expected in ("CWE-284", "CWE-269", "CWE-250", "CWE-1104", "CWE-494"):
        assert expected in cwes, f"IaC scanner should flag {expected}"


def test_iac_specific_detections():
    classes = {f.vuln_class for f in scan_iac(IAC, "x")}
    assert "iac-tf-s3-public-acl" in classes  # public-read S3
    assert "iac-tf-open-security-group" in classes  # 0.0.0.0/0 ingress
    assert "iac-iam-wildcard-policy" in classes  # Action "*" on Resource "*"
    assert "iac-k8s-privileged-container" in classes  # privileged: true
    assert "iac-docker-remote-pipe-shell" in classes  # curl ... | sh
    assert "iac-docker-no-user" in classes  # no USER -> root
    assert any(c in classes for c in ("iac-k8s-latest-image-tag", "iac-docker-latest-base-image"))  # :latest


def test_iac_findings_are_static_tier_with_location():
    findings = scan_iac(IAC, "x")
    assert findings, "fixtures should yield findings"
    for f in findings:
        assert f.verification.validated is False
        assert f.verification.method == "iac-static"
        assert f.confidence == "firm"
        assert "iac" in f.tags
        assert f.affected_code and f.affected_code.file and f.affected_code.start_line > 0
        assert f.cwe, "every finding carries a CWE"
        f.assert_consistent()


def test_iac_clean_file_yields_nothing(tmp_path):
    safe = tmp_path / "safe.tf"
    safe.write_text(
        'resource "aws_s3_bucket" "safe" {\n  bucket = "rampart-safe-bucket"\n  acl    = "private"\n}\n',
        encoding="utf-8",
    )
    assert scan_iac(str(tmp_path), "x") == []


def test_iac_missing_path_is_graceful():
    assert scan_iac("nonexistent") == []
    assert scan_iac("") == []
