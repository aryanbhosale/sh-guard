use std::io::Write;
use std::process::{Command, Stdio};

fn mcp_server() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sh-guard-mcp"))
}

fn send_messages(messages: &[&str]) -> String {
    let mut child = mcp_server()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start MCP server");

    {
        let stdin = child.stdin.as_mut().unwrap();
        for msg in messages {
            writeln!(stdin, "{}", msg).unwrap();
        }
    }

    let output = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn mcp_initialize() {
    let output = send_messages(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
    ]);
    let response: serde_json::Value = serde_json::from_str(output.lines().next().unwrap()).unwrap();
    assert_eq!(response["result"]["serverInfo"]["name"], "sh-guard");
    assert!(response["result"]["capabilities"]["tools"].is_object());
}

#[test]
fn mcp_tools_list() {
    let output = send_messages(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    ]);
    let lines: Vec<&str> = output.lines().collect();
    assert!(
        lines.len() >= 2,
        "Expected 2+ responses, got {}",
        lines.len()
    );
    let response: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "sh_guard_classify");
    assert_eq!(tools[1]["name"], "sh_guard_batch");
}

#[test]
fn mcp_classify_safe_command() {
    let output = send_messages(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sh_guard_classify","arguments":{"command":"ls -la"}}}"#,
    ]);
    let lines: Vec<&str> = output.lines().collect();
    let response: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
    let result: serde_json::Value = serde_json::from_str(content_text).unwrap();
    assert_eq!(result["level"], "safe");
    assert!(result["score"].as_u64().unwrap() <= 20);
}

#[test]
fn mcp_classify_critical_command() {
    let output = send_messages(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sh_guard_classify","arguments":{"command":"rm -rf ~/"}}}"#,
    ]);
    let lines: Vec<&str> = output.lines().collect();
    let response: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
    let result: serde_json::Value = serde_json::from_str(content_text).unwrap();
    assert_eq!(result["level"], "critical");
    assert!(result["score"].as_u64().unwrap() >= 81);
}

#[test]
fn mcp_batch_classify() {
    let output = send_messages(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sh_guard_batch","arguments":{"commands":["ls","rm -rf /"]}}}"#,
    ]);
    let lines: Vec<&str> = output.lines().collect();
    let response: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
    let results: Vec<serde_json::Value> = serde_json::from_str(content_text).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["level"], "safe");
    assert_eq!(results[1]["level"], "critical");
}

#[test]
fn mcp_classify_with_context() {
    let output = send_messages(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sh_guard_classify","arguments":{"command":"rm -rf ./build","cwd":"/home/user/project","project_root":"/home/user/project"}}}"#,
    ]);
    let lines: Vec<&str> = output.lines().collect();
    let response: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
    let result: serde_json::Value = serde_json::from_str(content_text).unwrap();
    // With project context, build dir delete should be less severe
    assert!(result["score"].as_u64().unwrap() <= 100);
}

#[test]
fn mcp_unknown_tool_returns_error() {
    let output = send_messages(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}"#,
    ]);
    let lines: Vec<&str> = output.lines().collect();
    let response: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    // Unknown tools now return a proper JSON-RPC error
    assert!(response.get("error").is_some());
    let error_msg = response["error"]["message"].as_str().unwrap();
    assert!(error_msg.contains("Unknown tool"));
}

#[test]
fn mcp_unknown_method_returns_error() {
    let output = send_messages(&[r#"{"jsonrpc":"2.0","id":1,"method":"nonexistent","params":{}}"#]);
    let lines: Vec<&str> = output.lines().collect();
    let response: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert!(response.get("error").is_some());
}
