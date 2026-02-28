# 🎵 VibeCheck

Security auditor for vibe-coded repos — 95% deterministic, 25x cheaper than competitors.

## Installation

```bash
pip install vibe-check-cli
```

## Setup API Keys

VibeCheck uses LLMs for intelligent compliance testing and hallucination detection.

### Local Development

You can simply create a `.env` file in the root of your repository where you run `vibe-check`. VibeCheck will automatically load it.

```bash
# .env
GEMINI_API_KEY="your-api-key-here"
```

### GitHub Actions (Production / CI / CD)

When running VibeCheck in GitHub Actions, pass the API key from your GitHub Repository Secrets as an environment variable to the step.

```yaml
- name: Run VibeCheck Scan
  env:
    GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
  run: vibe-check scan .
```

## Usage

Run a full security scan on the current directory:

```bash
vibe-check scan .
```

Get a quick score:

```bash
vibe-check score .
```
