#!/usr/bin/env python3
"""Subprocess-based tests for scan-secrets.py and scan-file-read.py (stdlib + unittest)."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from typing import Any

SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "src")
SCAN_SECRETS = os.path.join(SRC_DIR, "scan-secrets.py")
SCAN_FILE_READ = os.path.join(SRC_DIR, "scan-file-read.py")


def run_scan_secrets(payload: dict[str, Any]) -> dict[str, Any]:
    result = subprocess.run(
        ["python3", SCAN_SECRETS],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    err = result.stderr or ""
    if result.returncode != 0:
        raise AssertionError(
            f"scan-secrets exited {result.returncode}: stderr={err!r} stdout={result.stdout!r}"
        )
    return json.loads(result.stdout)


def run_scan_file_read(payload: dict[str, Any]) -> dict[str, Any]:
    result = subprocess.run(
        ["python3", SCAN_FILE_READ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"scan-file-read exited {result.returncode}: stderr={result.stderr!r} stdout={result.stdout!r}"
        )
    return json.loads(result.stdout)


# --- A. Pattern detection (one test per pattern) ---


class TestPatternDetection(unittest.TestCase):
    def test_private_key_pem_header(self) -> None:
        prompt = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."  # gitleaks:allow
        r = run_scan_secrets({"prompt": prompt})
        self.assertFalse(r["continue"])

    def test_aws_access_key(self) -> None:
        r = run_scan_secrets({"prompt": "here AKIAZBCDEFGHIJ123456 end"})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_aws_secret_key_assignment(self) -> None:
        line = (
            "aws_secret_access_key = "  # gitleaks:allow
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYabcdefghij"  # gitleaks:allow
        )
        r = run_scan_secrets({"prompt": line})
        self.assertFalse(r["continue"])

    def test_github_pat_classic(self) -> None:
        tok = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"  # gitleaks:allow
        r = run_scan_secrets({"prompt": f"token {tok}"})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_github_pat_fine_grained(self) -> None:
        tok = "github_pat_" + ("A" * 82)  # gitleaks:allow
        r = run_scan_secrets({"prompt": tok})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_github_oauth_token(self) -> None:
        tok = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"  # gitleaks:allow
        r = run_scan_secrets({"prompt": tok})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_gitlab_pat(self) -> None:
        tok = "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab"  # gitleaks:allow
        r = run_scan_secrets({"prompt": tok})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_openai_api_key(self) -> None:
        tok = "sk-ABCDEFGHIJKLMNOPQRSTUabcdefghij1234567890"  # gitleaks:allow
        r = run_scan_secrets({"prompt": tok})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_slack_token(self) -> None:
        tok = "xoxb-123456789012-1234567890123-ABCDEFGhijklmnop"  # gitleaks:allow
        r = run_scan_secrets({"prompt": tok})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_openshift_token(self) -> None:
        tok = "sha256~" + ("A" * 43)  # gitleaks:allow
        r = run_scan_secrets({"prompt": tok})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_url_embedded_credentials(self) -> None:
        r = run_scan_secrets(
            {"prompt": "https://admin:secretpass123@db.example.com:5432/mydb"}  # gitleaks:allow
        )
        self.assertFalse(r["continue"])

    def test_secret_assignment(self) -> None:
        r = run_scan_secrets({"prompt": "password=SuperSecret123!"})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_container_registry_auth(self) -> None:
        r = run_scan_secrets(
            {"prompt": '"auth": "dXNlcm5hbWU6cGFzc3dvcmQ="'}  # gitleaks:allow
        )
        self.assertFalse(r["continue"])

    def test_hugging_face_token(self) -> None:
        tok = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"  # gitleaks:allow
        r = run_scan_secrets({"prompt": tok})  # gitleaks:allow
        self.assertFalse(r["continue"])

    def test_stripe_live_key(self) -> None:
        r = run_scan_secrets(
            {"prompt": "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZab"}  # gitleaks:allow
        )
        self.assertFalse(r["continue"])


# --- B. Clean prompts ---


class TestCleanPrompts(unittest.TestCase):
    def test_normal_english(self) -> None:
        r = run_scan_secrets(
            {
                "prompt": (
                    "Summarize the quarterly report and list three action items "
                    "for the engineering team."
                )
            }
        )
        self.assertTrue(r["continue"])

    def test_python_code_no_secrets(self) -> None:
        r = run_scan_secrets(
            {
                "prompt": (
                    "def factorial(n):\n"
                    "    return 1 if n <= 1 else n * factorial(n - 1)\n"
                )
            }
        )
        self.assertTrue(r["continue"])

    def test_markdown_headings_code_fences(self) -> None:
        r = run_scan_secrets(
            {
                "prompt": (
                    "## Design\n\n"
                    "```python\n"
                    "print('hello')\n"
                    "```\n"
                )
            }
        )
        self.assertTrue(r["continue"])

    def test_security_discussion_no_real_secrets(self) -> None:
        r = run_scan_secrets(
            {
                "prompt": (
                    "Explain OWASP ASVS categories and how threat modeling "
                    "reduces credential exposure in web apps."
                )
            }
        )
        self.assertTrue(r["continue"])

    def test_short_hello(self) -> None:
        r = run_scan_secrets({"prompt": "hello"})
        self.assertTrue(r["continue"])

    def test_empty_prompt(self) -> None:
        r = run_scan_secrets({"prompt": ""})
        self.assertTrue(r["continue"])


# --- C. Allowlist ---


class TestAllowlist(unittest.TestCase):
    def test_placeholder_angle_brackets(self) -> None:
        r = run_scan_secrets({"prompt": "api_key=<YOUR_API_KEY>"})
        self.assertTrue(r["continue"])

    def test_aws_documentation_example_key(self) -> None:
        r = run_scan_secrets({"prompt": "AKIAIOSFODNN7EXAMPLE"})  # gitleaks:allow
        self.assertTrue(r["continue"])

    def test_password_changeme(self) -> None:
        r = run_scan_secrets({"prompt": "password=changeme"})
        self.assertTrue(r["continue"])

    def test_todo_placeholder(self) -> None:
        r = run_scan_secrets({"prompt": "secret=TODO_replace_this"})
        self.assertTrue(r["continue"])

    def test_fake_placeholder(self) -> None:
        r = run_scan_secrets({"prompt": "token=fake_token_here"})
        self.assertTrue(r["continue"])

    def test_brain_allow_suppression(self) -> None:
        r = run_scan_secrets(
            {"prompt": "password=realSecret123 # brain:allow"}  # gitleaks:allow
        )
        self.assertTrue(r["continue"])

    def test_gitleaks_allow_suppression(self) -> None:
        r = run_scan_secrets(
            {"prompt": "token=realToken456 # gitleaks:allow"}  # gitleaks:allow
        )
        self.assertTrue(r["continue"])

    def test_notsecret_suppression(self) -> None:
        r = run_scan_secrets(
            {"prompt": "api_key=realKey789 # notsecret"}  # gitleaks:allow
        )
        self.assertTrue(r["continue"])


# --- D. Edge cases ---


class TestEdgeCases(unittest.TestCase):
    def test_empty_json_object(self) -> None:
        r = run_scan_secrets({})
        self.assertTrue(r["continue"])

    def test_missing_prompt_field(self) -> None:
        r = run_scan_secrets({"model": "test"})
        self.assertTrue(r["continue"])

    def test_invalid_json_fail_open(self) -> None:
        result = subprocess.run(
            ["python3", SCAN_SECRETS],
            input="not json",
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        r = json.loads(result.stdout)
        self.assertTrue(r["continue"])

    def test_very_long_prompt(self) -> None:
        body = "The quick brown fox jumps over the lazy dog. " * 250
        self.assertGreaterEqual(len(body), 10000)
        r = run_scan_secrets({"prompt": body})
        self.assertTrue(r["continue"])

    def test_multiple_secrets_in_prompt(self) -> None:
        p = (
            "keys: AKIAZBCDEFGHIJ123456 and "  # gitleaks:allow
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"  # gitleaks:allow
        )
        r = run_scan_secrets({"prompt": p})
        self.assertFalse(r["continue"])
        msg = r.get("user_message", "")
        self.assertIn("AWS Access Key", msg)
        self.assertIn("GitHub PAT (classic)", msg)

    def test_unicode_prompt(self) -> None:
        r = run_scan_secrets({"prompt": "こんにちは — café résumé 测试"})
        self.assertTrue(r["continue"])


# --- E. Attachments ---


class TestAttachments(unittest.TestCase):
    def test_attachment_file_with_secret_blocked(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("AKIAZBCDEFGHIJ123456\n")  # gitleaks:allow
            path = f.name
        try:
            r = run_scan_secrets(
                {
                    "prompt": "see file",
                    "attachments": [{"type": "file", "file_path": path}],
                }
            )
            self.assertFalse(r["continue"])
        finally:
            os.unlink(path)

    def test_attachment_file_clean_allowed(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("just notes\n")
            path = f.name
        try:
            r = run_scan_secrets(
                {
                    "prompt": "see file",
                    "attachments": [{"type": "file", "file_path": path}],
                }
            )
            self.assertTrue(r["continue"])
        finally:
            os.unlink(path)

    def test_attachment_missing_file_allowed(self) -> None:
        r = run_scan_secrets(
            {
                "prompt": "ok",
                "attachments": [
                    {"type": "file", "file_path": "/no/such/path/file.txt"}
                ],
            }
        )
        self.assertTrue(r["continue"])

    def test_attachment_type_rule_skipped(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("AKIAZBCDEFGHIJ123456\n")  # gitleaks:allow
            path = f.name
        try:
            r = run_scan_secrets(
                {
                    "prompt": "rule ref",
                    "attachments": [{"type": "rule", "file_path": path}],
                }
            )
            self.assertTrue(r["continue"])
        finally:
            os.unlink(path)


# --- F. File read hook ---


class TestScanFileRead(unittest.TestCase):
    def test_aws_key_in_content_denies(self) -> None:
        r = run_scan_file_read(
            {
                "file_path": "/tmp/app.cfg",
                "content": "key=AKIAZBCDEFGHIJ123456\n",  # gitleaks:allow
            }
        )
        self.assertEqual(r["permission"], "deny")

    def test_clean_content_allows(self) -> None:
        r = run_scan_file_read(
            {
                "file_path": "/src/utils.py",
                "content": "def add(a, b):\n    return a + b\n",
            }
        )
        self.assertEqual(r.get("permission"), "allow")

    def test_png_extension_skipped_allows(self) -> None:
        r = run_scan_file_read(
            {
                "file_path": "/assets/logo.png",
                "content": "AKIAZBCDEFGHIJ123456",  # gitleaks:allow
            }
        )
        self.assertEqual(r.get("permission"), "allow")

    def test_node_modules_path_skipped_allows(self) -> None:
        r = run_scan_file_read(
            {
                "file_path": "/proj/node_modules/foo/index.js",
                "content": "AKIAZBCDEFGHIJ123456",  # gitleaks:allow
            }
        )
        self.assertEqual(r.get("permission"), "allow")

    def test_empty_content_allows(self) -> None:
        r = run_scan_file_read({"file_path": "/x.txt", "content": ""})
        self.assertEqual(r.get("permission"), "allow")

    def test_missing_content_allows(self) -> None:
        r = run_scan_file_read({"file_path": "/x.txt"})
        self.assertEqual(r.get("permission"), "allow")


# --- G. Output format ---


class TestOutputFormat(unittest.TestCase):
    def test_blocked_has_continue_and_user_message(self) -> None:
        r = run_scan_secrets({"prompt": "AKIAZBCDEFGHIJ123456"})  # gitleaks:allow
        self.assertFalse(r["continue"])
        self.assertIn("user_message", r)
        self.assertIsInstance(r["user_message"], str)

    def test_user_message_contains_pattern_name(self) -> None:
        r = run_scan_secrets({"prompt": "password=SuperSecret123!"})  # gitleaks:allow
        self.assertFalse(r["continue"])
        msg = r["user_message"]
        self.assertIn("Secret assignment", msg)

    def test_user_message_redacts_match(self) -> None:
        secret = "SuperSecret123!"  # gitleaks:allow
        r = run_scan_secrets({"prompt": f"password={secret}"})  # gitleaks:allow
        self.assertFalse(r["continue"])
        msg = r["user_message"]
        self.assertNotIn(secret, msg)

    def test_deny_has_permission_and_user_message(self) -> None:
        r = run_scan_file_read(
            {
                "file_path": "/secrets.env",
                "content": "AWS=AKIAZBCDEFGHIJ123456",  # gitleaks:allow
            }
        )
        self.assertEqual(r["permission"], "deny")
        self.assertIn("user_message", r)
        self.assertIn("AWS Access Key", r["user_message"])


if __name__ == "__main__":
    unittest.main()
