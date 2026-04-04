use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Agent definitions
// ---------------------------------------------------------------------------

struct Agent {
    name: &'static str,
    kind: AgentKind,
    config_path: fn() -> Option<PathBuf>,
}

enum AgentKind {
    /// Agents with PreToolUse hooks (Claude Code, Codex)
    Hook,
    /// Agents that use MCP servers only (Cursor, Cline, Windsurf, Continue)
    Mcp,
}

fn home() -> Option<PathBuf> {
    dirs_next().or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
}

fn dirs_next() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

fn claude_code_config() -> Option<PathBuf> {
    home().map(|h| h.join(".claude").join("settings.json"))
}

fn codex_hooks_config() -> Option<PathBuf> {
    home().map(|h| h.join(".codex").join("hooks.json"))
}

fn cursor_config() -> Option<PathBuf> {
    home().map(|h| h.join(".cursor").join("mcp.json"))
}

fn cline_config() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        home().map(|h| {
            h.join("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")
        })
    }
    #[cfg(target_os = "linux")]
    {
        home().map(|h| {
            h.join(".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")
        })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(|a| {
            PathBuf::from(a).join(
                "Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            )
        })
    }
}

fn windsurf_config() -> Option<PathBuf> {
    home().map(|h| h.join(".codeium").join("windsurf").join("mcp_config.json"))
}

const AGENTS: &[Agent] = &[
    Agent {
        name: "Claude Code",
        kind: AgentKind::Hook,
        config_path: claude_code_config,
    },
    Agent {
        name: "Codex CLI",
        kind: AgentKind::Hook,
        config_path: codex_hooks_config,
    },
    Agent {
        name: "Cursor",
        kind: AgentKind::Mcp,
        config_path: cursor_config,
    },
    Agent {
        name: "Cline",
        kind: AgentKind::Mcp,
        config_path: cline_config,
    },
    Agent {
        name: "Windsurf",
        kind: AgentKind::Mcp,
        config_path: windsurf_config,
    },
];

// ---------------------------------------------------------------------------
// Hook script
// ---------------------------------------------------------------------------

const HOOK_SCRIPT: &str = r#"#!/bin/sh
# sh-guard PreToolUse hook — blocks dangerous commands before execution
COMMAND=$(cat | jq -r '.tool_input.command // empty' 2>/dev/null)
[ -z "$COMMAND" ] && exit 0
RESULT=$(sh-guard --json --exit-code "$COMMAND" 2>&1)
EC=$?
if [ "$EC" -eq 3 ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "Blocked by sh-guard"' 2>/dev/null)
  echo "sh-guard BLOCKED: $REASON" >&2
  exit 2
fi
exit 0
"#;

fn hook_script_path() -> Option<PathBuf> {
    home().map(|h| h.join(".sh-guard").join("hook.sh"))
}

fn ensure_hook_script() -> Result<PathBuf, String> {
    let path = hook_script_path().ok_or("Cannot determine home directory")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    fs::write(&path, HOOK_SCRIPT).map_err(|e| format!("Failed to write hook script: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&path, perms)
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    Ok(path)
}

// ---------------------------------------------------------------------------
// Config modification
// ---------------------------------------------------------------------------

fn read_json_or_empty(path: &Path) -> Value {
    if path.exists() {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    }
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }
    let contents =
        serde_json::to_string_pretty(value).map_err(|e| format!("Failed to serialize: {}", e))?;
    fs::write(path, contents.as_bytes())
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))
}

fn setup_claude_code(config_path: &Path, hook_path: &Path) -> Result<bool, String> {
    let mut config = read_json_or_empty(config_path);

    // Check if hook already exists
    if let Some(hooks) = config.get("hooks").and_then(|h| h.get("PreToolUse")) {
        if let Some(arr) = hooks.as_array() {
            for entry in arr {
                if let Some(inner) = entry.get("hooks").and_then(|h| h.as_array()) {
                    for hook in inner {
                        if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                            if cmd.contains("sh-guard") {
                                return Ok(false); // Already configured
                            }
                        }
                    }
                }
            }
        }
    }

    let hook_entry = json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": hook_path.to_string_lossy(),
            "timeout": 1000
        }]
    });

    let hooks = config
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let pre = hooks
        .as_object_mut()
        .unwrap()
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    pre.as_array_mut().unwrap().push(hook_entry);

    write_json(config_path, &config)?;
    Ok(true)
}

fn setup_codex(config_path: &Path, hook_path: &Path) -> Result<bool, String> {
    let mut config = read_json_or_empty(config_path);

    // Check if hook already exists
    if let Some(hooks) = config.get("hooks").and_then(|h| h.get("PreToolUse")) {
        if let Some(arr) = hooks.as_array() {
            for entry in arr {
                if let Some(inner) = entry.get("hooks").and_then(|h| h.as_array()) {
                    for hook in inner {
                        if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                            if cmd.contains("sh-guard") {
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        }
    }

    let hook_entry = json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": hook_path.to_string_lossy(),
            "timeout": 30
        }]
    });

    let hooks = config
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let pre = hooks
        .as_object_mut()
        .unwrap()
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    pre.as_array_mut().unwrap().push(hook_entry);

    write_json(config_path, &config)?;
    Ok(true)
}

fn setup_mcp(config_path: &Path) -> Result<bool, String> {
    let mut config = read_json_or_empty(config_path);

    // Check if already configured
    if let Some(servers) = config.get("mcpServers") {
        if servers.get("sh-guard").is_some() {
            return Ok(false);
        }
    }

    let mcp_entry = json!({
        "command": "sh-guard-mcp"
    });

    let servers = config
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}));
    servers
        .as_object_mut()
        .unwrap()
        .insert("sh-guard".to_string(), mcp_entry);

    write_json(config_path, &config)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn run_setup() {
    println!("sh-guard setup — configuring AI coding agents\n");

    // Check that sh-guard and sh-guard-mcp are on PATH
    let sh_guard_available = which_exists("sh-guard");
    let mcp_available = which_exists("sh-guard-mcp");
    let jq_available = which_exists("jq");

    if !sh_guard_available {
        println!("  Warning: 'sh-guard' not found on PATH");
        println!("  Install it first: brew install aryanbhosale/tap/sh-guard\n");
    }

    if !jq_available {
        println!("  Warning: 'jq' not found on PATH (needed for hook script)");
        println!("  Install it: brew install jq  /  apt install jq\n");
    }

    // Write the hook script
    let hook_path = match ensure_hook_script() {
        Ok(p) => {
            println!("  Hook script: {}", p.display());
            p
        }
        Err(e) => {
            eprintln!("  Error creating hook script: {}", e);
            return;
        }
    };

    println!();

    let mut configured = 0u32;
    let mut skipped = 0u32;
    let mut not_found = 0u32;

    for agent in AGENTS {
        let config_path = match (agent.config_path)() {
            Some(p) => p,
            None => {
                println!("  {} — skipped (cannot determine path)", agent.name);
                not_found += 1;
                continue;
            }
        };

        // For MCP agents, only configure if the config dir exists
        // (indicates the agent is installed)
        let agent_installed = match agent.kind {
            AgentKind::Hook => {
                // For Claude Code: ~/.claude/ should exist
                // For Codex: ~/.codex/ should exist
                config_path.parent().map(|p| p.exists()).unwrap_or(false)
            }
            AgentKind::Mcp => {
                // Check if the parent directory (or grandparent for nested paths) exists
                config_path.parent().map(|p| p.exists()).unwrap_or(false)
            }
        };

        if !agent_installed {
            println!("  {} — not installed", agent.name);
            not_found += 1;
            continue;
        }

        let result = match agent.kind {
            AgentKind::Hook => match agent.name {
                "Claude Code" => setup_claude_code(&config_path, &hook_path),
                "Codex CLI" => setup_codex(&config_path, &hook_path),
                _ => Err("Unknown hook agent".to_string()),
            },
            AgentKind::Mcp => {
                if !mcp_available {
                    println!("  {} — skipped (sh-guard-mcp not on PATH)", agent.name);
                    skipped += 1;
                    continue;
                }
                setup_mcp(&config_path)
            }
        };

        match result {
            Ok(true) => {
                println!("  {} — configured ✓", agent.name);
                configured += 1;
            }
            Ok(false) => {
                println!("  {} — already configured", agent.name);
                skipped += 1;
            }
            Err(e) => {
                println!("  {} — error: {}", agent.name, e);
            }
        }
    }

    println!();
    println!(
        "Done: {} configured, {} already set, {} not installed",
        configured, skipped, not_found
    );

    if configured > 0 {
        println!("\nRestart your AI agents for changes to take effect.");
    }
}

pub fn run_uninstall() {
    println!("sh-guard uninstall — removing from AI coding agents\n");

    for agent in AGENTS {
        let config_path = match (agent.config_path)() {
            Some(p) if p.exists() => p,
            _ => continue,
        };

        let result = match agent.kind {
            AgentKind::Hook => remove_hook(&config_path),
            AgentKind::Mcp => remove_mcp(&config_path),
        };

        match result {
            Ok(true) => println!("  {} — removed", agent.name),
            Ok(false) => println!("  {} — was not configured", agent.name),
            Err(e) => println!("  {} — error: {}", agent.name, e),
        }
    }

    // Remove hook script
    if let Some(path) = hook_script_path() {
        if path.exists() {
            let _ = fs::remove_file(&path);
            println!("\n  Removed hook script: {}", path.display());
        }
    }

    println!("\nDone.");
}

fn remove_hook(config_path: &Path) -> Result<bool, String> {
    let mut config = read_json_or_empty(config_path);
    let mut removed = false;

    if let Some(hooks) = config.get_mut("hooks") {
        if let Some(pre) = hooks.get_mut("PreToolUse") {
            if let Some(arr) = pre.as_array_mut() {
                let before = arr.len();
                arr.retain(|entry| {
                    if let Some(inner) = entry.get("hooks").and_then(|h| h.as_array()) {
                        !inner.iter().any(|hook| {
                            hook.get("command")
                                .and_then(|c| c.as_str())
                                .map(|c| c.contains("sh-guard"))
                                .unwrap_or(false)
                        })
                    } else {
                        true
                    }
                });
                removed = arr.len() < before;
            }
        }
    }

    if removed {
        write_json(config_path, &config)?;
    }
    Ok(removed)
}

fn remove_mcp(config_path: &Path) -> Result<bool, String> {
    let mut config = read_json_or_empty(config_path);

    let removed = config
        .get_mut("mcpServers")
        .and_then(|s| s.as_object_mut())
        .map(|servers| servers.remove("sh-guard").is_some())
        .unwrap_or(false);

    if removed {
        write_json(config_path, &config)?;
    }
    Ok(removed)
}

fn which_exists(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
