"""IaC precision/recall regressions: CloudFormation detection, ingress-vs-egress, comments,
per-statement IAM evaluation, multi-line cidr lists, more K8s workload kinds, final-stage
Dockerfile USER, and untagged base images."""

import os

from rampart.iac import scan_iac


def _scan(tmp_path, files: dict):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return sorted(
        (f.affected_code.file, f.affected_code.start_line, f.vuln_class) for f in scan_iac(str(tmp_path))
    )


def test_non_cfn_yaml_with_lowercase_resources_is_not_cloudformation(tmp_path):
    got = _scan(
        tmp_path,
        {
            "values.yaml": "replicaCount: 2\nresources:\n  limits:\n    cpu: 100m\ningress:\n"
            '  whitelistSourceRange: "0.0.0.0/0"\npersistence:\n  encrypted: false\n',
            ".github/workflows/ci.yml": "name: ci\njobs:\n  build:\n    resources:\n"
            '      note: "dns 0.0.0.0/0 default route"\n',
        },
    )
    assert got == []


def test_cfn_egress_and_strings_are_not_open_ingress(tmp_path):
    got = _scan(
        tmp_path,
        {
            "tmpl.yaml": 'AWSTemplateFormatVersion: "2010-09-09"\n'
            "Resources:\n"
            "  SG:\n"
            "    Type: AWS::EC2::SecurityGroup\n"
            "    Properties:\n"
            '      GroupDescription: "allow egress to 0.0.0.0/0 only"\n'
            "      SecurityGroupEgress:\n"
            "        - IpProtocol: -1\n"
            "          CidrIp: 0.0.0.0/0\n"
            "      SecurityGroupIngress:\n"
            "        - IpProtocol: tcp\n"
            "          CidrIp: 0.0.0.0/0\n"
            "  Out:\n"
            "    Type: AWS::EC2::SecurityGroupEgress\n"
            "    Properties:\n"
            "      CidrIp: 0.0.0.0/0\n"
            "  Policy:\n"
            "    Type: AWS::IAM::ManagedPolicy\n"
            "    Properties:\n"
            "      PolicyDocument:\n"
            "        Statement:\n"
            "          - Effect: Deny\n"
            '            Action: "*"\n'
            '            Resource: "*"\n'
            "          - Effect: Allow\n"
            '            Action: "*"\n'
            '            Resource: "*"\n',
        },
    )
    assert got == [
        ("tmpl.yaml", 12, "iac-cfn-open-security-group"),
        ("tmpl.yaml", 26, "iac-iam-wildcard-policy"),
    ]


def test_terraform_egress_comments_multiline_and_per_statement_iam(tmp_path):
    got = _scan(
        tmp_path,
        {
            "bad.tf": 'resource "aws_security_group" "open" {\n'
            "  ingress {\n"
            "    from_port   = 22\n"
            "    cidr_blocks = [\n"
            '      "0.0.0.0/0",\n'
            "    ]\n"
            "  }\n"
            "}\n",
            "good.tf": 'resource "aws_security_group" "locked" {\n'
            "  egress {\n"
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            "  }\n"
            "}\n"
            'resource "aws_security_group_rule" "out" {\n'
            '  type        = "egress"\n'
            '  cidr_blocks = ["0.0.0.0/0"]\n'
            "}\n"
            'resource "aws_iam_policy" "deny" {\n'
            "  policy = jsonencode({\n"
            '    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]\n'
            "  })\n"
            "}\n"
            'resource "aws_iam_policy" "two" {\n'
            "  policy = jsonencode({\n"
            "    Statement = [\n"
            '      { Effect = "Allow", Action = "*", Resource = "arn:aws:s3:::x" },\n'
            '      { Effect = "Allow", Action = "s3:GetObject", Resource = "*" },\n'
            "    ]\n"
            "  })\n"
            "}\n"
            '# acl = "public-read" was the old value\n'
            '// acl = "public-read-write"\n'
            '/* cidr_blocks = ["0.0.0.0/0"] */\n',
        },
    )
    assert got == [("bad.tf", 4, "iac-tf-open-security-group")]


def test_k8s_cronjob_and_per_document_securitycontext(tmp_path):
    got = _scan(
        tmp_path,
        {
            "cronjob.yaml": "apiVersion: batch/v1\nkind: CronJob\nspec:\n  jobTemplate:\n    spec:\n"
            "      template:\n        spec:\n          containers:\n          - name: c\n"
            "            image: busybox:latest\n            securityContext:\n"
            "              privileged: true\n",
            "multi.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n---\n"
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n"
            "      - name: c\n        image: myrepo/app:1.2.3\n",
            "commented.yaml": "apiVersion: v1\nkind: Pod\nspec:\n  # hostNetwork: true\n"
            "  securityContext:\n    runAsNonRoot: true\n  containers:\n  - name: c\n    image: a:1\n",
        },
    )
    assert got == [
        ("cronjob.yaml", 10, "iac-k8s-latest-image-tag"),
        ("cronjob.yaml", 12, "iac-k8s-privileged-container"),
        ("multi.yaml", 7, "iac-k8s-missing-securitycontext"),
    ]


def test_dockerfile_final_stage_user_and_untagged_base(tmp_path):
    got = _scan(
        tmp_path,
        {
            "multistage/Dockerfile": "FROM golang:1.22 AS build\nUSER builder\nRUN go build -o /app\n"
            'FROM debian:12\nCOPY --from=build /app /app\nCMD ["/app"]\n',
            "rootuser/Dockerfile": 'FROM python:3.12-slim\nUSER root\nCMD ["python","app.py"]\n',
            "notag/Dockerfile": "FROM ubuntu\nUSER 1000\n",
            "good/Dockerfile": "FROM python:3.12-slim@sha256:abc\nRUN useradd -m app\nUSER app\n"
            "# RUN curl https://x | sh\n",
            "stagealias/Dockerfile": "FROM node:20 AS deps\nFROM deps\nUSER node\n",
        },
    )
    assert got == [
        ("multistage/Dockerfile", 4, "iac-docker-no-user"),
        ("notag/Dockerfile", 1, "iac-docker-latest-base-image"),
        ("rootuser/Dockerfile", 2, "iac-docker-root-user"),
    ]


def test_demo_iac_findings_unchanged():
    iac = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples", "demo_target", "iac"))
    got = sorted((f.affected_code.file, f.affected_code.start_line, f.vuln_class) for f in scan_iac(iac))
    assert got == [
        ("Dockerfile", 3, "iac-docker-latest-base-image"),
        ("Dockerfile", 3, "iac-docker-no-user"),
        ("Dockerfile", 8, "iac-docker-remote-pipe-shell"),
        ("Dockerfile", 11, "iac-docker-add-remote-url"),
        ("deployment.yaml", 17, "iac-k8s-host-network"),
        ("deployment.yaml", 20, "iac-k8s-latest-image-tag"),
        ("deployment.yaml", 24, "iac-k8s-privileged-container"),
        ("deployment.yaml", 25, "iac-k8s-run-as-root"),
        ("main.tf", 6, "iac-tf-s3-public-acl"),
        ("main.tf", 11, "iac-tf-encryption-disabled"),
        ("main.tf", 23, "iac-tf-open-security-group"),
        ("main.tf", 35, "iac-iam-wildcard-policy"),
    ]
