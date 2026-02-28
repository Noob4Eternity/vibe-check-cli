# 🎵 VibeCheck

**Security auditor for vibe-coded repos** — 95% deterministic, 25x cheaper than competitors.

VibeCheck scans your codebase for hard-coded secrets, SAST vulnerabilities, dependency issues, prompt injection surfaces, and compliance gaps — all in one command.

## Installation

```bash
pip install vibe-check-cli
```

## Quick Start

```bash
# Full scan on the current directory
vibe-check scan .

# Quick score only
vibe-check score .

# Initialize config + git hook
vibe-check init
```

---

## Commands

### `vibe-check scan`

🔍 Run a full security scan on a repository.

```bash
vibe-check scan [PATH] [OPTIONS]
```

| Argument / Option   | Default    | Description                                      |
| ------------------- | ---------- | ------------------------------------------------ |
| `PATH`              | `.`        | Path to the repository to scan                   |
| `--mode`, `-m`      | `full`     | Scan mode: `fast` (no LLM) or `full`             |
| `--format`, `-f`    | `terminal` | Output format: `terminal`, `json`, or `markdown` |
| `--exit-code`, `-e` | `false`    | Exit with code 1 if score is below threshold     |
| `--threshold`, `-t` | `60`       | Score threshold for `--exit-code`                |
| `--severity`, `-s`  | _(all)_    | Filter findings: `critical,high,medium,low,info` |

**Examples:**

```bash
# Scan a specific project
vibe-check scan /path/to/project

# Fast scan (skip LLM-based analyzers — no API key needed)
vibe-check scan . --mode fast

# JSON output for CI pipelines
vibe-check scan . --format json

# Fail CI if score is below 70
vibe-check scan . --exit-code --threshold 70

# Show only critical and high severity findings
vibe-check scan . --severity critical,high
```

---

### `vibe-check score`

📊 Quick score — just the number and grade, no detailed findings.

```bash
vibe-check score [PATH] [OPTIONS]
```

| Argument / Option   | Default | Description                                  |
| ------------------- | ------- | -------------------------------------------- |
| `PATH`              | `.`     | Path to the repository                       |
| `--exit-code`, `-e` | `false` | Exit with code 1 if score is below threshold |
| `--threshold`, `-t` | `60`    | Score threshold for `--exit-code`            |

**Example:**

```bash
vibe-check score .
# Output: 82/100  B  MOSTLY SAFE
```

---

### `vibe-check init`

⚙️ Initialize a `.vibecheck.yml` config file and install a pre-push git hook.

```bash
vibe-check init
```

This creates:

- **`.vibecheck.yml`** — Configuration file with default settings
- **`.git/hooks/pre-push`** — Git hook that runs a fast scan before every push

---

### Global Options

| Option            | Description                |
| ----------------- | -------------------------- |
| `--version`, `-v` | Show the installed version |
| `--help`          | Show help for any command  |

---

## Configuration

### API Keys

VibeCheck uses LLMs for compliance analysis and prompt injection detection. In `fast` mode, no API key is needed.

#### Local Development

Create a `.env` file in your project root:

```bash
# .env
GEMINI_API_KEY="your-api-key-here"
```

#### GitHub Actions

Pass the API key from your repository secrets:

```yaml
- name: Run VibeCheck Scan
  env:
    GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
  run: vibe-check scan . --exit-code
```

### `.vibecheck.yml`

Customize scan behavior by adding a `.vibecheck.yml` to your project root:

```yaml
# Scan mode: fast (no LLM) or full
mode: full

# Score threshold for --exit-code
threshold: 60

# Severity filter (empty = all)
severity_filter: []

# Directories to always skip (safety net for non-git repos)
exclude:
  - node_modules/
  - .venv/
  - __pycache__/

# LLM settings
llm:
  provider: gemini # gemini, openai, or anthropic
  token_budget: 5000
```

### Environment Variables

| Variable                  | Description                     |
| ------------------------- | ------------------------------- |
| `GEMINI_API_KEY`          | API key for Google Gemini       |
| `VIBE_CHECK_API_KEY`      | Override API key (any provider) |
| `VIBE_CHECK_PROVIDER`     | Override LLM provider           |
| `VIBE_CHECK_TOKEN_BUDGET` | Override token budget           |

---

## What It Scans

| Analyzer                | What it detects                           | Mode       |
| ----------------------- | ----------------------------------------- | ---------- |
| 🔑 **Secrets**          | Hard-coded API keys, tokens, passwords    | fast, full |
| 🛡️ **SAST**             | SQL injection, XSS, eval(), insecure CORS | fast, full |
| 📦 **Dependencies**     | Known CVEs in pip/npm packages            | fast, full |
| 🤖 **Prompt Injection** | Unsanitized user input → LLM calls        | fast, full |
| 🔍 **Hallucination**    | Phantom imports and non-existent packages | fast, full |
| 📋 **Compliance**       | GDPR, SOC2, OWASP gaps                    | full       |
| 💡 **LLM Summarizer**   | AI-generated remediation for all findings | full       |

---

## File Exclusion

VibeCheck uses a **two-layer strategy** to skip irrelevant files:

1. **Git tracking** — In git repos, only git-tracked files are scanned (automatically respects `.gitignore`)
2. **Hardcoded safety net** — `node_modules`, `.venv`, `venv`, `env`, and `__pycache__` are always skipped, even in non-git directories
