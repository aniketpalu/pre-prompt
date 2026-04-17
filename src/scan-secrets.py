#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from patterns import scan_text  # noqa: E402


def _read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _format_block_message(findings: list[dict]) -> str:
    lines = []
    for f in findings:
        name = f.get("pattern_name", "match")
        red = f.get("matched_redacted", "…")
        loc = f.get("source_label", "")
        if loc == "prompt text":
            where = "in prompt text"
        else:
            where = f"in attached file {loc}"
        lines.append(f"  • {name} ({red}) {where}")
    body = "\n".join(lines)
    n = len(findings)
    return (
        "⚠ SECRET DETECTED — Prompt blocked\n\n"
        f"Found {n} potential credential{'s' if n != 1 else ''}:\n"
        f"{body}\n\n"
        "Remove the credentials and try again.\n"
        "To suppress a false positive, add 'notsecret' next to the value."
    )


def main() -> None:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(json.dumps({"continue": True}, ensure_ascii=False))
        return

    prompt = data.get("prompt") or ""
    if not isinstance(prompt, str):
        prompt = str(prompt)

    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []

    findings: list[dict] = []
    findings.extend(scan_text(prompt, "prompt text"))

    for att in attachments:
        if not isinstance(att, dict):
            continue
        if att.get("type") != "file":
            continue
        fp = att.get("file_path")
        if not fp or not isinstance(fp, str):
            continue
        content = _read_file(fp)
        if content is None:
            continue
        findings.extend(scan_text(content, fp))

    if findings:
        print(
            json.dumps(
                {
                    "continue": False,
                    "user_message": _format_block_message(findings),
                },
                ensure_ascii=False,
            )
        )
    else:
        print(json.dumps({"continue": True}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
