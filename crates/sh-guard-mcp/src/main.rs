use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = request.get("id").cloned();
        let params = request.get("params").cloned().unwrap_or(json!({}));

        let response = match method {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "sh-guard",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                });
                Some(json_rpc_response(id, result))
            }
            "notifications/initialized" => {
                // Notification -- no response needed
                None
            }
            "tools/list" => {
                let result = json!({
                    "tools": [
                        {
                            "name": "sh_guard_classify",
                            "description": "Analyze a shell command for security risks before execution. Returns risk score (0-100), risk level (safe/caution/danger/critical), intent classification, target identification, data-flow analysis for pipelines, and MITRE ATT&CK technique mapping.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": {
                                        "type": "string",
                                        "description": "The shell command to analyze"
                                    },
                                    "cwd": {
                                        "type": "string",
                                        "description": "Current working directory for context-aware analysis"
                                    },
                                    "project_root": {
                                        "type": "string",
                                        "description": "Project root directory -- commands inside this boundary score lower"
                                    },
                                    "home_dir": {
                                        "type": "string",
                                        "description": "User home directory"
                                    },
                                    "shell": {
                                        "type": "string",
                                        "enum": ["bash", "zsh"],
                                        "default": "bash",
                                        "description": "Shell type (bash or zsh) -- affects zsh-specific rule detection"
                                    }
                                },
                                "required": ["command"]
                            }
                        },
                        {
                            "name": "sh_guard_batch",
                            "description": "Analyze multiple shell commands at once. Returns an array of analysis results.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "commands": {
                                        "type": "array",
                                        "items": { "type": "string" },
                                        "description": "Array of shell commands to analyze"
                                    },
                                    "cwd": { "type": "string" },
                                    "project_root": { "type": "string" },
                                    "shell": {
                                        "type": "string",
                                        "enum": ["bash", "zsh"],
                                        "default": "bash"
                                    }
                                },
                                "required": ["commands"]
                            }
                        }
                    ]
                });
                Some(json_rpc_response(id, result))
            }
            "tools/call" => {
                let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

                match tool_name {
                    "sh_guard_classify" => {
                        let result = handle_classify(&arguments);
                        Some(json_rpc_response(id, result))
                    }
                    "sh_guard_batch" => {
                        let result = handle_batch(&arguments);
                        Some(json_rpc_response(id, result))
                    }
                    _ => Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32602,
                            "message": format!("Unknown tool: {}", tool_name)
                        }
                    })),
                }
            }
            _ => {
                // Unknown method -- return error if it has an id (request), ignore if notification
                if id.is_some() {
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": format!("Method not found: {}", method)
                        }
                    }))
                } else {
                    None
                }
            }
        };

        if let Some(resp) = response {
            let Ok(resp_str) = serde_json::to_string(&resp) else {
                continue;
            };
            if writeln!(stdout, "{}", resp_str).is_err() || stdout.flush().is_err() {
                break;
            }
        }
    }
}

fn handle_classify(arguments: &Value) -> Value {
    let command = arguments
        .get("command")
        .and_then(|c| c.as_str())
        .unwrap_or("");

    let ctx = build_context(arguments);
    let result = sh_guard_core::classify(command, ctx.as_ref());

    let result_json = serde_json::to_string_pretty(&result).unwrap_or_default();

    json!({
        "content": [{
            "type": "text",
            "text": result_json
        }]
    })
}

fn handle_batch(arguments: &Value) -> Value {
    let commands: Vec<String> = arguments
        .get("commands")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let ctx = build_context(arguments);
    let strs: Vec<&str> = commands.iter().map(|s| s.as_str()).collect();
    let results = sh_guard_core::classify_batch(&strs, ctx.as_ref());

    let result_json = serde_json::to_string_pretty(&results).unwrap_or_default();

    json!({
        "content": [{
            "type": "text",
            "text": result_json
        }]
    })
}

fn build_context(args: &Value) -> Option<sh_guard_core::ClassifyContext> {
    let has_any = args.get("cwd").is_some()
        || args.get("project_root").is_some()
        || args.get("home_dir").is_some()
        || args.get("shell").is_some();

    if !has_any {
        return None;
    }

    Some(sh_guard_core::ClassifyContext {
        cwd: args.get("cwd").and_then(|v| v.as_str()).map(String::from),
        project_root: args
            .get("project_root")
            .and_then(|v| v.as_str())
            .map(String::from),
        home_dir: args
            .get("home_dir")
            .and_then(|v| v.as_str())
            .map(String::from),
        protected_paths: vec![],
        shell: match args.get("shell").and_then(|v| v.as_str()) {
            Some("zsh") => sh_guard_core::Shell::Zsh,
            _ => sh_guard_core::Shell::Bash,
        },
    })
}

fn json_rpc_response(id: Option<Value>, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "result": result
    })
}
