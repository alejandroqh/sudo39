# sudo39

sudo39 is a small MCP server built with [TurboMCP](https://github.com/Epistates/turbomcp). Its primary tool is:

> **WARNING:** With great power comes great responsibility. This server grants elevated OS privileges to AI agents. Misconfiguration can allow arbitrary root-level execution. Read the full Elevation Model section before deploying.

```text
sudo_run(command, arguments?, mode?)
```

Harmless example MCP tool arguments:

```json
{
  "command": "id",
  "mode": "auto"
}
```

Prefer structured arguments when possible:

```json
{
  "command": "systemctl",
  "arguments": ["restart", "nginx"],
  "mode": "sudo"
}
```

## Elevation Model

`sudo39` intentionally does not accept a password parameter. Passwords sent through an MCP client can end up in model context, logs, traces, shell history, and transcripts. Configure elevation on the host instead:

- Linux: `sudo` in `auto` mode, or `pkexec` if `sudo` cannot run. Set `SUDO39_ASKPASS` to let `sudo -A` ask for credentials through an askpass helper.
- macOS: `auto` uses `osascript` with the native administrator prompt.
- Windows: `auto` uses PowerShell `Start-Process -Verb RunAs` to trigger UAC.

By default, every program is denied. Configure one of these before startup:

```sh
# Safer: allow only named programs.
export SUDO39_ALLOWED_PROGRAMS=id,whoami,systemctl

# Unsafe: allow arbitrary elevated programs.
export SUDO39_ALLOW_UNSAFE=1
```

The startup environment seeds the runtime policy. You can also change the active policy for the running server through MCP admin tools:

- `sudo39_policy()`
- `sudo39_add_allowed_program(program, confirmation)`
- `sudo39_remove_allowed_program(program, confirmation)`
- `sudo39_set_allow_unsafe(enabled, confirmation)`
- `sudo39_reload_policy_from_env(confirmation)`

Each mutating admin tool requires an exact confirmation phrase. Use these MCP prompts to generate the phrase shown to the user:

- `confirm_add_allowed_program(program)`
- `confirm_remove_allowed_program(program)`
- `confirm_set_allow_unsafe(enabled)`
- `confirm_reload_policy_from_env()`

Example flow:

```text
prompt: confirm_add_allowed_program("id")
tool: sudo39_add_allowed_program(program: "id", confirmation: "ADD PROGRAM id")
```

Unsafe mode is also gated:

```text
prompt: confirm_set_allow_unsafe("true")
tool: sudo39_set_allow_unsafe(enabled: true, confirmation: "ENABLE UNSAFE")
```

These changes are in-memory only. Restarting the server returns to the policy from `SUDO39_ALLOWED_PROGRAMS` and `SUDO39_ALLOW_UNSAFE`.

`sudo39_reload_policy_from_env` replaces the in-memory policy with the server process environment. This is only useful when that process environment has been changed by the supervisor or launcher; editing a shell variable elsewhere does not modify the environment of an already-running process.

When making dependent calls, wait for the admin tool response before calling `sudo_run` or `sudo39_policy`. JSON-RPC requests may be handled concurrently, so sending several requests at once does not guarantee policy update ordering.

Runtime limits default to 30 seconds and 4 KiB (~1000 LLM tokens) per output stream:

```sh
export SUDO39_TIMEOUT_SECS=30
export SUDO39_OUTPUT_LIMIT_BYTES=4096
```

For `sudo` password prompts, set `SUDO39_ASKPASS` to an askpass helper controlled by the same trust boundary as the MCP server:

```sh
export SUDO39_ASKPASS=/absolute/path/to/askpass
```

Modes:

- `auto`
- `sudo`
- `pkexec`
- `macos_osascript`
- `windows_uac`

## Install

```bash
cargo install sudo39
```

### Install for any AI CLI / IDE

Installs the binary and auto-configures it for every MCP client detected: **Claude Code**, **Claude Desktop**, **Codex**, **OpenCode**, **OpenClaw**.

```sh
curl -fsSL https://raw.githubusercontent.com/alejandroqh/marketplace/main/h39.sh | sh
```

## Build

```sh
cargo build --release
```

## MCP Client Config

For a stdio MCP client:

```json
{
  "mcpServers": {
    "sudo39": {
      "command": "/absolute/path/to/sudo39",
      "args": []
    }
  }
}
```

## Notes

Any MCP client granted access to this server can request elevated operations allowed by your active policy. If the client can call the admin tools, it can also expand that active policy after the confirmation step. Treat the client, server process environment, and askpass helper as the administrative trust boundary.

`sudo` cannot safely prompt for a password on MCP stdio, because stdin/stdout are already the protocol transport. If no askpass helper is configured, `sudo39` runs `sudo -n`, which fails instead of prompting. This is deliberate.

Commands are executed without a shell on Linux and Windows. On macOS, the administrator prompt path uses AppleScript's `do shell script`; `sudo39` shell-quotes the program and argument vector before passing it to AppleScript. Pass arguments with the `arguments` array; `command` must be a single program path.

The returned `launcher_exit_status`, `stdout`, and `stderr` are captured from the elevation launcher and capped by `SUDO39_OUTPUT_LIMIT_BYTES`. On Linux this is normally the elevated command through `sudo` or `pkexec`. On macOS it is `osascript`. On Windows it is the PowerShell `Start-Process` launcher, not a reliable capture of the elevated child process output.

Each execution or policy change writes a minimal audit event to stderr with timestamp and relevant policy or command fields. It does not log stdout or stderr.
