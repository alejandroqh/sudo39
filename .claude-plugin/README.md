# sudo39 - Claude Bundle Plugin

This directory makes sudo39 installable as an OpenClaw **Claude bundle**.

## Install

```bash
# From local directory
openclaw plugins install ./path/to/sudo39

# Or from archive
openclaw plugins install ./sudo39.tgz
```

## What it provides

OpenClaw detects this as a Claude bundle and maps the MCP server config from `.mcp.json`.
The sudo39 binary runs as a stdio MCP subprocess, exposing all tools:

- `sudo_run` - run a command through the host OS elevation mechanism
- `sudo39_policy` - show the active runtime policy
- `sudo39_add_allowed_program` - add a program to the runtime allowlist
- `sudo39_remove_allowed_program` - remove a program from the runtime allowlist
- `sudo39_set_allow_unsafe` - turn runtime unsafe mode on or off
- `sudo39_reload_policy_from_env` - reload the runtime policy from environment variables

## Requirements

The `sudo39` binary must be in PATH, or update `.mcp.json` to point to the binary location.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `SUDO39_ALLOWED_PROGRAMS` | (empty) | Comma-separated allowlist |
| `SUDO39_ALLOW_UNSAFE` | (unset) | Set to `1` to allow any program |
| `SUDO39_TIMEOUT_SECS` | 30 | Per-execution timeout |
| `SUDO39_OUTPUT_LIMIT_BYTES` | 4096 | Max bytes captured per stream |
| `SUDO39_ASKPASS` | (unset) | Path to askpass helper for `sudo -A` |
