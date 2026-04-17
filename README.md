# pre-prompt

A credential scanner that catches secrets **before they reach the AI model**. Built as native [Cursor hooks](https://cursor.com/docs/agent/hooks) — no extension required.

> **Cursor only for now.** VS Code extension is planned.

## How It Works

Every time you submit a prompt or the agent reads a file, pre-prompt checks for credentials and **blocks the action** if any are found. The secret never leaves your machine.

```
You hit Send
  -> Cursor spawns the scanner
  -> Scans prompt text + attached files for 15 credential patterns
  -> Clean? Prompt goes through.
  -> Secret found? Blocked with a clear warning.
```

### What Gets Caught

| Vector | Hook |
|--------|------|
| You type or paste a credential into chat | `beforeSubmitPrompt` |
| You attach a file containing secrets | `beforeSubmitPrompt` |
| The agent reads a file with credentials into context | `beforeReadFile` |
| Tab autocomplete reads a file with credentials | `beforeTabFileRead` |

### 15 Credential Patterns

| Pattern | Examples |
|---------|----------|
| Private keys | `-----BEGIN RSA PRIVATE KEY-----` | <!-- gitleaks:allow -->
| AWS access keys | `AKIA...`, `ASIA...` |
| AWS secret keys | `aws_secret_access_key = ...` |
| GitHub PATs | `ghp_...`, `github_pat_...`, `gho_...` |
| GitLab PATs | `glpat-...` |
| OpenAI API keys | `sk-...` |
| Slack tokens | `xoxb-...`, `xoxp-...` |
| OpenShift tokens | `sha256~...` |
| URL credentials | `https://user:pass@host` |
| Secret assignments | `password=...`, `token=...`, `api_key=...` |
| Container registry auth | `"auth": "base64..."` |
| Hugging Face tokens | `hf_...` |
| Stripe / SendGrid keys | `sk_live_...`, `SG....` |

## Requirements

- [Cursor](https://cursor.com) (v1.0+)
- Python 3.8+
- No pip packages — stdlib only

## Quick Start

```bash
git clone https://github.com/<your-username>/pre-prompt.git
cd pre-prompt
./install.sh --global
```

That's it. Restart Cursor (or run `Developer: Reload Window`) and you're protected.

## Installation

### Option A: Global (all your projects)

```bash
./install.sh --global
```

This copies the scanner to `~/.cursor/hooks/` and creates `~/.cursor/hooks.json`. Every project you open in Cursor gets scanning.

### Option B: Project-level (single repo)

```bash
cd /path/to/your/project
/path/to/pre-prompt/install.sh --project
```

This copies the scanner to `.cursor/hooks/` in your project and creates `.cursor/hooks.json`. Commit these files so your whole team gets scanning.

### Option C: Manual

Copy the three files from `src/` into your hooks directory:

```bash
mkdir -p ~/.cursor/hooks
cp src/patterns.py src/scan-secrets.py src/scan-file-read.py ~/.cursor/hooks/
```

Then create `~/.cursor/hooks.json` (or `.cursor/hooks.json` in your project):

```json
{
  "version": 1,
  "hooks": {
    "beforeSubmitPrompt": [
      {
        "command": "python3 ./hooks/scan-secrets.py",
        "failClosed": true
      }
    ],
    "beforeReadFile": [
      {
        "command": "python3 ./hooks/scan-file-read.py",
        "failClosed": true
      }
    ],
    "beforeTabFileRead": [
      {
        "command": "python3 ./hooks/scan-file-read.py",
        "failClosed": true
      }
    ]
  }
}
```

For project-level hooks, change paths from `./hooks/` to `.cursor/hooks/`.

### Verify

Check **Cursor Settings > Hooks** — all 3 hooks should appear. If not, run `Developer: Reload Window`.

## What You See

When a secret is detected, your prompt is blocked:

```
⚠ SECRET DETECTED — Prompt blocked

Found 1 potential credential:
  • AWS Access Key (AKIA...MPLE) in prompt text

Remove the credentials and try again.
To suppress a false positive, add 'notsecret' next to the value.
```

When a file read is blocked:

```
⚠ SECRET DETECTED — File read blocked

File: /path/to/config.env
Found 2 potential credentials:
  • AWS Access Key (AKIA...3456)
  • Secret assignment (pass...rd12)

This file contains credentials and was not sent to the model.
```

## Suppressing False Positives

Add a suppression marker on the same line:

```
password=not_a_real_secret  # notsecret
token=test_fixture_value    # gitleaks:allow
api_key=dev_only_key        # brain:allow
```

Placeholder values are automatically skipped:

```
api_key=<YOUR_API_KEY>          # not flagged (angle brackets)
password=changeme               # not flagged (placeholder)
token=TODO_replace_this         # not flagged (TODO)
```

## Adding Custom Patterns

Edit `patterns.py` and add entries to the `PATTERNS` list:

```python
{
    "name": "My Custom Token",
    "regex": re.compile(r"myco_[A-Za-z0-9]{32}"),
    "description": "MyCompany API token",
},
```

## Skipping File Types

`scan-file-read.py` automatically skips:
- Binary files: `.png`, `.jpg`, `.zip`, `.exe`, `.pyc`, etc.
- Vendor directories: `node_modules`, `vendor`, `__pycache__`, `.venv`

Edit `SKIP_EXTENSIONS` and `SKIP_PATH_SEGMENTS` in `scan-file-read.py` to customize.

## Configuration

### `failClosed`

All hooks default to `failClosed: true`. If the scanner crashes or times out, the action is **blocked** rather than allowed through. Set to `false` if you prefer fail-open.

## Running Tests

```bash
python3 -m pytest tests/test_scan_secrets.py -v
```

49 tests covering all 15 patterns, allowlist behavior, edge cases, attachments, and output format.

## Project Structure

```
pre-prompt/
├── README.md
├── LICENSE
├── install.sh              # One-command installer
├── hooks.json.example      # Example Cursor hooks config
├── src/
│   ├── patterns.py         # 15 regex patterns + allowlist
│   ├── scan-secrets.py     # beforeSubmitPrompt hook
│   └── scan-file-read.py   # beforeReadFile + beforeTabFileRead hook
└── tests/
    ├── test_scan_secrets.py
    └── fixtures/
        ├── fake-credentials.txt
        ├── clean-prompt.txt
        ├── false-positives.txt
        └── secret-test-file.env
```

## Limitations

- **Block only** — hooks cannot redact or modify prompts, only allow or block
- **Cursor only** — VS Code support planned as a separate extension
- **No entropy checks** — relies on pattern matching; may miss high-entropy random strings
- **Hooks are a Cursor preview feature** — the API may change

## Contributing

1. Fork the repo
2. Add patterns to `src/patterns.py`
3. Add matching tests to `tests/test_scan_secrets.py`
4. Run `python3 -m pytest tests/ -v` and make sure all tests pass
5. Open a PR

## License

MIT
