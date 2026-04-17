#!/usr/bin/env python3
"""Credential scan for Cursor beforeReadFile / beforeTabFileRead hooks (stdlib only)."""

from __future__ import annotations

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from patterns import scan_text  # noqa: E402

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4",
    ".zip", ".tar", ".gz", ".bin",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".class",
}

SKIP_PATH_SEGMENTS = {
    "node_modules", "vendor", "__pycache__", ".venv", "venv",
}


def should_skip(file_path: str) -> bool:
    if not file_path:
        return False
    norm = os.path.normpath(file_path)
    ext = os.path.splitext(norm)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return True
    parts = norm.split(os.sep)
    if SKIP_PATH_SEGMENTS & set(parts):
        return True
    try:
        gi = parts.index(".git")
        if gi + 1 < len(parts) and parts[gi + 1] == "objects":
            return True
    except ValueError:
        pass
    return False


def _format_deny_message(file_path: str, findings: list[dict]) -> str:
    lines = [
        "⚠ SECRET DETECTED — File read blocked",
        "",
        f"File: {file_path}",
        f"Found {len(findings)} potential credential{'s' if len(findings) != 1 else ''}:",
    ]
    for f in findings:
        name = f.get("pattern_name", "unknown")
        red = f.get("matched_redacted", "…")
        lines.append(f"  • {name} ({red})")
    lines.append("")
    lines.append("This file contains credentials and was not sent to the model.")
    return "\n".join(lines)


def main() -> None:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print(json.dumps({"permission": "allow"}))
        return

    file_path = payload.get("file_path") or ""
    content = payload.get("content")

    if content is None or content == "":
        print(json.dumps({"permission": "allow"}))
        return

    if not isinstance(content, str):
        print(json.dumps({"permission": "allow"}))
        return

    if should_skip(file_path):
        print(json.dumps({"permission": "allow"}))
        return

    try:
        findings = scan_text(content, file_path)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    if findings:
        msg = _format_deny_message(file_path, findings)
        print(json.dumps({"permission": "deny", "user_message": msg}))
    else:
        print(json.dumps({"permission": "allow"}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
