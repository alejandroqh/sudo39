use std::{
    collections::HashSet,
    io::Read,
    process::{Command, Output, Stdio},
    sync::{Arc, RwLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use turbomcp::prelude::*;

#[derive(Clone)]
struct Sudo39 {
    policy: Arc<RwLock<Policy>>,
}

#[server(
    name = "sudo39",
    version = "0.1.0",
    description = "MCP server exposing a guarded OS elevation tool."
)]
impl Sudo39 {
    fn from_env() -> Self {
        Self {
            policy: Arc::new(RwLock::new(Policy::from_env())),
        }
    }

    #[tool("Run a command through the host OS elevation mechanism.")]
    async fn sudo_run(
        &self,
        #[description(
            "Program to run, for example \"id\". Must be a single program path; pass arguments with the arguments parameter."
        )]
        command: String,
        #[description(
            "Optional arguments passed directly to the program. Prefer this over shell-style command strings."
        )]
        arguments: Option<Vec<String>>,
        #[description("Elevation mode: auto, sudo, pkexec, macos_osascript, or windows_uac.")]
        mode: Option<String>,
    ) -> McpResult<String> {
        let request = CommandRequest::new(command, arguments)?;
        let mode = ElevationMode::parse(mode.as_deref())?;

        if let Err(error) = validate_request(&self.policy, &request) {
            audit_request("deny", mode, &request, None);
            return Err(error);
        }
        audit_request("start", mode, &request, None);
        let blocking_request = request.clone();
        let result = match tokio::task::spawn_blocking(move || mode.run(&blocking_request)).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                audit_request("error", mode, &request, None);
                return Err(McpError::internal(error));
            }
            Err(error) => {
                audit_request("error", mode, &request, None);
                return Err(McpError::internal(error.to_string()));
            }
        };
        audit_request("finish", mode, &request, result.output.status.code());

        Ok(format_output(&request, mode, &result))
    }

    #[tool("Show the active sudo39 runtime policy.")]
    async fn sudo39_policy(&self) -> McpResult<String> {
        let policy = read_policy(&self.policy)?;
        Ok(policy.describe())
    }

    #[tool("Add a program to the runtime allowlist after explicit confirmation.")]
    async fn sudo39_add_allowed_program(
        &self,
        #[description(
            "Program path to allow. It must match the command field passed to sudo_run."
        )]
        program: String,
        #[description("Exact confirmation phrase from the confirm_add_allowed_program prompt.")]
        confirmation: String,
    ) -> McpResult<String> {
        let program = normalize_program(program)?;
        let expected = confirm_add_program_phrase(&program);
        require_confirmation(&confirmation, &expected)?;

        let mut policy = write_policy(&self.policy)?;
        policy.allowed_programs.insert(program.clone());
        audit_policy_update("add_allowed_program", &program);

        Ok(format!("allowed program added: {program}"))
    }

    #[tool("Remove a program from the runtime allowlist after explicit confirmation.")]
    async fn sudo39_remove_allowed_program(
        &self,
        #[description("Program path to remove from the runtime allowlist.")] program: String,
        #[description("Exact confirmation phrase from the confirm_remove_allowed_program prompt.")]
        confirmation: String,
    ) -> McpResult<String> {
        let program = normalize_program(program)?;
        let expected = confirm_remove_program_phrase(&program);
        require_confirmation(&confirmation, &expected)?;

        let mut policy = write_policy(&self.policy)?;
        policy.allowed_programs.remove(&program);
        audit_policy_update("remove_allowed_program", &program);

        Ok(format!("allowed program removed: {program}"))
    }

    #[tool("Turn runtime unsafe mode on or off after explicit confirmation.")]
    async fn sudo39_set_allow_unsafe(
        &self,
        #[description("true to allow any program, false to return to allowlist enforcement.")]
        enabled: bool,
        #[description("Exact confirmation phrase from the confirm_set_allow_unsafe prompt.")]
        confirmation: String,
    ) -> McpResult<String> {
        let expected = confirm_unsafe_phrase(enabled);
        require_confirmation(&confirmation, expected)?;

        let mut policy = write_policy(&self.policy)?;
        policy.allow_unsafe = enabled;
        audit_policy_update("set_allow_unsafe", if enabled { "true" } else { "false" });

        Ok(format!("allow unsafe set to {enabled}"))
    }

    #[tool("Reload the runtime policy from SUDO39_ALLOWED_PROGRAMS and SUDO39_ALLOW_UNSAFE.")]
    async fn sudo39_reload_policy_from_env(
        &self,
        #[description("Exact confirmation phrase from the confirm_reload_policy_from_env prompt.")]
        confirmation: String,
    ) -> McpResult<String> {
        require_confirmation(&confirmation, confirm_reload_policy_phrase())?;

        let reloaded = Policy::from_env();
        let description = reloaded.describe();
        let mut policy = write_policy(&self.policy)?;
        *policy = reloaded;
        audit_policy_update(
            "reload_from_env",
            "SUDO39_ALLOWED_PROGRAMS,SUDO39_ALLOW_UNSAFE",
        );

        Ok(format!("policy reloaded from environment\n{description}"))
    }

    #[prompt("Create a confirmation phrase for allowing a program at runtime.")]
    async fn confirm_add_allowed_program(&self, program: String, _ctx: &RequestContext) -> String {
        let program = program.trim();
        format!(
            "To allow {program:?} for this running sudo39 server, call sudo39_add_allowed_program with confirmation exactly: {}",
            confirm_add_program_phrase(program)
        )
    }

    #[prompt("Create a confirmation phrase for removing a program from the runtime allowlist.")]
    async fn confirm_remove_allowed_program(
        &self,
        program: String,
        _ctx: &RequestContext,
    ) -> String {
        let program = program.trim();
        format!(
            "To remove {program:?} from this running sudo39 server, call sudo39_remove_allowed_program with confirmation exactly: {}",
            confirm_remove_program_phrase(program)
        )
    }

    #[prompt("Create a confirmation phrase for switching runtime unsafe mode on or off.")]
    async fn confirm_set_allow_unsafe(&self, enabled: String, _ctx: &RequestContext) -> String {
        let enabled = matches!(enabled.trim(), "true" | "1" | "on" | "yes");
        format!(
            "To set runtime unsafe mode to {enabled}, call sudo39_set_allow_unsafe with confirmation exactly: {}",
            confirm_unsafe_phrase(enabled)
        )
    }

    #[prompt("Create a confirmation phrase for reloading policy from the process environment.")]
    async fn confirm_reload_policy_from_env(&self, _ctx: &RequestContext) -> String {
        format!(
            "To replace the runtime policy with the process environment, call sudo39_reload_policy_from_env with confirmation exactly: {}",
            confirm_reload_policy_phrase()
        )
    }
}

#[derive(Debug)]
struct Policy {
    allowed_programs: HashSet<String>,
    allow_unsafe: bool,
}

impl Policy {
    fn from_env() -> Self {
        let allowed_programs = std::env::var("SUDO39_ALLOWED_PROGRAMS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(ToString::to_string)
            .collect();

        Self {
            allowed_programs,
            allow_unsafe: std::env::var("SUDO39_ALLOW_UNSAFE").ok().as_deref() == Some("1"),
        }
    }

    fn describe(&self) -> String {
        let mut allowed_programs = self.allowed_programs.iter().collect::<Vec<_>>();
        allowed_programs.sort();

        format!(
            "allow_unsafe: {}\nallowed_programs: {:?}",
            self.allow_unsafe, allowed_programs
        )
    }
}

#[derive(Clone, Debug)]
struct CommandRequest {
    program: String,
    args: Vec<String>,
}

impl CommandRequest {
    fn new(command: String, args: Option<Vec<String>>) -> McpResult<Self> {
        Ok(Self {
            program: normalize_program(command)?,
            args: args.unwrap_or_default(),
        })
    }
}

fn validate_request(policy: &Arc<RwLock<Policy>>, request: &CommandRequest) -> McpResult<()> {
    let policy = read_policy(policy)?;

    if policy.allow_unsafe {
        return Ok(());
    }

    if policy.allowed_programs.contains(&request.program) {
        return Ok(());
    }

    Err(McpError::permission_denied(
        "program is not allowed; set SUDO39_ALLOWED_PROGRAMS or SUDO39_ALLOW_UNSAFE=1",
    ))
}

fn read_policy(policy: &Arc<RwLock<Policy>>) -> McpResult<std::sync::RwLockReadGuard<'_, Policy>> {
    policy
        .read()
        .map_err(|_| McpError::internal("policy lock poisoned"))
}

fn write_policy(
    policy: &Arc<RwLock<Policy>>,
) -> McpResult<std::sync::RwLockWriteGuard<'_, Policy>> {
    policy
        .write()
        .map_err(|_| McpError::internal("policy lock poisoned"))
}

fn normalize_program(program: String) -> McpResult<String> {
    let program = program.trim();
    if program.is_empty() {
        return Err(McpError::invalid_params("program must not be empty"));
    }
    if program.contains(char::is_whitespace) {
        return Err(McpError::invalid_params(
            "program must be a single program path without whitespace",
        ));
    }
    Ok(program.to_string())
}

fn require_confirmation(actual: &str, expected: &str) -> McpResult<()> {
    if actual == expected {
        return Ok(());
    }

    Err(McpError::permission_denied(format!(
        "confirmation mismatch; expected {expected:?}"
    )))
}

fn confirm_add_program_phrase(program: &str) -> String {
    format!("ADD PROGRAM {program}")
}

fn confirm_remove_program_phrase(program: &str) -> String {
    format!("REMOVE PROGRAM {program}")
}

fn confirm_unsafe_phrase(enabled: bool) -> &'static str {
    if enabled {
        "ENABLE UNSAFE"
    } else {
        "DISABLE UNSAFE"
    }
}

fn confirm_reload_policy_phrase() -> &'static str {
    "RELOAD POLICY FROM ENV"
}

struct RunResult {
    launcher: &'static str,
    output: Output,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[derive(Clone, Copy, Debug)]
enum ElevationMode {
    Auto,
    Sudo,
    Pkexec,
    MacosOsascript,
    WindowsUac,
}

impl ElevationMode {
    fn parse(mode: Option<&str>) -> McpResult<Self> {
        match mode.unwrap_or("auto") {
            "auto" => Ok(Self::Auto),
            "sudo" => Ok(Self::Sudo),
            "pkexec" => Ok(Self::Pkexec),
            "macos_osascript" => Ok(Self::MacosOsascript),
            "windows_uac" => Ok(Self::WindowsUac),
            other => Err(McpError::invalid_params(format!(
                "unsupported elevation mode {other:?}; use auto, sudo, pkexec, macos_osascript, or windows_uac"
            ))),
        }
    }

    fn run(self, request: &CommandRequest) -> Result<RunResult, String> {
        match self {
            Self::Auto => run_elevated_auto(request),
            Self::Sudo => run_sudo(request),
            Self::Pkexec => run_pkexec(request),
            Self::MacosOsascript => run_macos_osascript(request),
            Self::WindowsUac => run_windows_uac(request),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Sudo => "sudo",
            Self::Pkexec => "pkexec",
            Self::MacosOsascript => "macos_osascript",
            Self::WindowsUac => "windows_uac",
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_elevated_auto(request: &CommandRequest) -> Result<RunResult, String> {
    if cfg!(target_os = "macos") {
        return run_macos_osascript(request);
    }

    run_sudo(request).or_else(|sudo_error| {
        run_pkexec(request).map_err(|pkexec_error| {
            format!("sudo failed: {sudo_error}; pkexec failed: {pkexec_error}")
        })
    })
}

#[cfg(target_os = "windows")]
fn run_elevated_auto(request: &CommandRequest) -> Result<RunResult, String> {
    run_windows_uac(request)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_elevated_auto(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("auto elevation is only implemented for Linux, macOS, and Windows".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_sudo(request: &CommandRequest) -> Result<RunResult, String> {
    let mut command = Command::new("sudo");
    if let Some(askpass) = std::env::var_os("SUDO39_ASKPASS") {
        command.env("SUDO_ASKPASS", askpass);
        command.arg("-A");
    } else {
        command.arg("-n");
    }

    command.arg("--").arg(&request.program).args(&request.args);
    run_command(command, "sudo").map_err(|error| format!("sudo failed: {error}"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run_sudo(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("sudo mode is only available on Linux and macOS".to_string())
}

#[cfg(target_os = "linux")]
fn run_pkexec(request: &CommandRequest) -> Result<RunResult, String> {
    let mut command = Command::new("pkexec");
    command.arg(&request.program).args(&request.args);
    run_command(command, "pkexec").map_err(|error| format!("pkexec failed: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn run_pkexec(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("pkexec mode is only available on Linux".to_string())
}

#[cfg(target_os = "macos")]
fn run_macos_osascript(request: &CommandRequest) -> Result<RunResult, String> {
    let shell_command = shell_join(request);
    let script = format!(
        "do shell script {} with administrator privileges",
        apple_script_string(&shell_command)
    );

    let mut command = Command::new("osascript");
    command.arg("-e").arg(script);
    run_command(command, "osascript").map_err(|error| format!("osascript failed: {error}"))
}

#[cfg(not(target_os = "macos"))]
fn run_macos_osascript(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("macos_osascript mode is only available on macOS".to_string())
}

#[cfg(target_os = "windows")]
fn run_windows_uac(request: &CommandRequest) -> Result<RunResult, String> {
    let arguments = request
        .args
        .iter()
        .map(|arg| format!("'{}'", powershell_single_quote(arg)))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "Start-Process -FilePath '{}' -ArgumentList @({}) -Verb RunAs -Wait",
        powershell_single_quote(&request.program),
        arguments
    );

    let mut command = Command::new("powershell.exe");
    command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(script);

    run_command(command, "powershell_start_process")
        .map_err(|error| format!("powershell UAC failed: {error}"))
}

#[cfg(not(target_os = "windows"))]
fn run_windows_uac(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("windows_uac mode is only available on Windows".to_string())
}

#[cfg(target_os = "macos")]
fn shell_join(request: &CommandRequest) -> String {
    std::iter::once(&request.program)
        .chain(request.args.iter())
        .map(|part| shell_single_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "macos")]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn apple_script_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "windows")]
fn powershell_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn run_command(mut command: Command, launcher: &'static str) -> Result<RunResult, String> {
    let timeout = env_u64("SUDO39_TIMEOUT_SECS", 30);
    let output_limit = env_u64("SUDO39_OUTPUT_LIMIT_BYTES", 4096) as usize;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture stderr".to_string())?;

    let stdout_reader = thread::spawn(move || read_limited(stdout, output_limit));
    let stderr_reader = thread::spawn(move || read_limited(stderr, output_limit));
    let deadline = SystemTime::now() + Duration::from_secs(timeout);

    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }

        if SystemTime::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = stdout_reader
                .join()
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default();
            let stderr = stderr_reader
                .join()
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default();
            let mut msg = format!("timed out after {timeout} seconds");
            let stdout_text = String::from_utf8_lossy(&stdout.0);
            let stderr_text = String::from_utf8_lossy(&stderr.0);
            if !stdout_text.is_empty() {
                msg.push_str(&format!("\npartial stdout:\n{stdout_text}"));
            }
            if !stderr_text.is_empty() {
                msg.push_str(&format!("\npartial stderr:\n{stderr_text}"));
            }
            return Err(msg);
        }

        thread::sleep(Duration::from_millis(50));
    };

    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| "stdout reader panicked".to_string())??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| "stderr reader panicked".to_string())??;

    Ok(RunResult {
        launcher,
        stdout_truncated,
        stderr_truncated,
        output: Output {
            status,
            stdout,
            stderr,
        },
    })
}

fn read_limited(mut reader: impl Read, limit: usize) -> Result<(Vec<u8>, bool), String> {
    let mut output = Vec::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Ok((output, false));
        }

        let remaining = limit - output.len();
        if remaining == 0 {
            // Drop the reader (closing the pipe) so the child gets SIGPIPE
            // instead of blocking us reading unbounded output we'd discard.
            return Ok((output, true));
        }
        output.extend_from_slice(&buffer[..count.min(remaining)]);
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn format_output(request: &CommandRequest, mode: ElevationMode, result: &RunResult) -> String {
    let status = result.output.status.code().map_or_else(
        || "terminated by signal".to_string(),
        |code| code.to_string(),
    );
    let stdout = String::from_utf8_lossy(&result.output.stdout);
    let stderr = String::from_utf8_lossy(&result.output.stderr);
    let stdout_suffix = if result.stdout_truncated {
        "\n[truncated]"
    } else {
        ""
    };
    let stderr_suffix = if result.stderr_truncated {
        "\n[truncated]"
    } else {
        ""
    };

    format!(
        "program: {}\nargs: {:?}\nmode: {}\nlauncher: {}\nlauncher_exit_status: {}\nstdout:\n{}{}\nstderr:\n{}{}",
        request.program,
        request.args,
        mode.as_str(),
        result.launcher,
        status,
        stdout,
        stdout_suffix,
        stderr,
        stderr_suffix,
    )
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn audit_request(event: &str, mode: ElevationMode, request: &CommandRequest, status: Option<i32>) {
    eprintln!(
        "sudo39_audit event={} unix_ts={} mode={} program={:?} args={:?} status={:?}",
        event,
        unix_ts(),
        mode.as_str(),
        request.program,
        request.args,
        status
    );
}

fn audit_policy_update(action: &str, value: &str) {
    eprintln!(
        "sudo39_audit event=policy_update unix_ts={} action={} value={:?}",
        unix_ts(),
        action,
        value
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Sudo39::from_env().run_stdio().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_program() {
        let request = CommandRequest::new(" id ".to_string(), None).unwrap();
        assert_eq!(request.program, "id");
        assert!(request.args.is_empty());
    }

    #[test]
    fn rejects_whitespace_in_program() {
        let error = CommandRequest::new("echo hello".to_string(), None).unwrap_err();
        assert!(error.message.contains("single program path"));
    }

    #[test]
    fn confirmation_phrases_are_exact() {
        assert_eq!(confirm_add_program_phrase("id"), "ADD PROGRAM id");
        assert_eq!(confirm_remove_program_phrase("id"), "REMOVE PROGRAM id");
        assert_eq!(confirm_unsafe_phrase(true), "ENABLE UNSAFE");
        assert_eq!(confirm_unsafe_phrase(false), "DISABLE UNSAFE");
        assert_eq!(confirm_reload_policy_phrase(), "RELOAD POLICY FROM ENV");
    }

    #[test]
    fn policy_describe_sorts_allowed_programs() {
        let policy = Policy {
            allowed_programs: ["whoami".to_string(), "id".to_string()].into(),
            allow_unsafe: false,
        };

        assert_eq!(
            policy.describe(),
            "allow_unsafe: false\nallowed_programs: [\"id\", \"whoami\"]"
        );
    }
}
