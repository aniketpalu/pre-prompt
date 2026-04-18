from __future__ import annotations

import re
from typing import Any

_SUPPRESSION_MARKERS = ("gitleaks:allow", "brain:allow", "notsecret")

_AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"

_PLACEHOLDER_LOWER = (
    "example",
    "xxx",
    "changeme",
    "todo",
    "replace_me",
    "your_",
    "insert_",
    "placeholder",
    "dummy",
    "fake",
    "test123",
)


def redact_match(match_text: str) -> str:
    if len(match_text) >= 12:
        return match_text[:4] + "..." + match_text[-4:]
    return (match_text[:4] if match_text else "") + "..."


def is_allowlisted(match_text: str, line: str) -> bool:
    if match_text == _AWS_EXAMPLE_KEY:
        return True
    if "<" in match_text or ">" in match_text:
        return True
    if "EXAMPLE" in match_text:
        return True
    mt_lower = match_text.lower()
    for ph in _PLACEHOLDER_LOWER:
        if ph in mt_lower:
            return True
    for s in _SUPPRESSION_MARKERS:
        if s in line:
            return True
    return False


def _line_at(text: str, pos: int) -> str:
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end]


def scan_text(text: str, source_label: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for p in PATTERNS:
        name = p["name"]
        regex: re.Pattern[str] = p["regex"]
        for m in regex.finditer(text):
            matched = m.group(0)
            line = _line_at(text, m.start())
            if is_allowlisted(matched, line):
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append(
                {
                    "pattern_name": name,
                    "matched_redacted": redact_match(matched),
                    "source_label": source_label,
                    "source": f"{source_label}:{line_no}",
                }
            )
    return findings


PATTERNS: list[dict[str, Any]] = [
    {
        "name": "Private key (PEM header)",
        "regex": re.compile(
            r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        ),
        "description": "PEM-encoded private key block header",
    },
    {
        "name": "AWS Access Key",
        "regex": re.compile(
            r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])",
        ),
        "description": "AWS access key ID",
    },
    {
        "name": "AWS secret key assignment",
        "regex": re.compile(
            r"(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        ),
        "description": "AWS secret key in assignment",
    },
    {
        "name": "GitHub PAT (classic)",
        "regex": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "description": "GitHub personal access token (classic)",
    },
    {
        "name": "GitHub PAT (fine-grained)",
        "regex": re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        "description": "GitHub fine-grained PAT",
    },
    {
        "name": "GitHub OAuth token",
        "regex": re.compile(r"gho_[A-Za-z0-9]{36}"),
        "description": "GitHub OAuth token",
    },
    {
        "name": "GitLab PAT",
        "regex": re.compile(r"glpat-[A-Za-z0-9\-]{20,}"),
        "description": "GitLab personal access token",
    },
    {
        "name": "OpenAI API key",
        "regex": re.compile(r"sk-(?!live_)[A-Za-z0-9]{20,}"),
        "description": "OpenAI-style API key (excludes Stripe sk_live_)",
    },
    {
        "name": "Slack token",
        "regex": re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}"),
        "description": "Slack bot/user token",
    },
    {
        "name": "OpenShift token",
        "regex": re.compile(r"sha256~[A-Za-z0-9_\-]{43}"),
        "description": "OpenShift OAuth token",
    },
    {
        "name": "URL embedded credentials",
        "regex": re.compile(r"://[^/\s:]+:[^/\s@]+@"),
        "description": "User:password in URL",
    },
    {
        "name": "Secret assignment",
        "regex": re.compile(
            r"""(?i)["\']?(?:\w+_)?(password|passwd|token|secret|api_key|apikey|access_key|client_secret)["\']?\s*[=:]\s*['\"]?[^\s'\"]{8,}""",
        ),
        "description": "Generic secret-like assignment (includes prefixed variants like client_secret, db_password, and JSON format)",
    },
    {
        "name": "Container registry auth",
        "regex": re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
        "description": "Docker config auth field",
    },
    {
        "name": "Hugging Face token",
        "regex": re.compile(r"hf_[A-Za-z0-9]{34}"),
        "description": "Hugging Face API token",
    },
    {
        "name": "Stripe / SendGrid key",
        "regex": re.compile(r"(sk_live_|rk_live_|SG\.)[A-Za-z0-9]{10,}"),
        "description": "Stripe live or SendGrid key pattern",
    },
]
