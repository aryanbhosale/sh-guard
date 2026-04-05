//! Custom rule engine — loads `.sh-guard.toml` or user-specified TOML files.
//!
//! Supports:
//! - Allowlists: commands that are always safe (score forced to 0)
//! - Blocklists: commands/patterns that are always critical (score forced to 100)
//! - Custom command rules with intent, weight, flags, and MITRE mappings
//! - Custom path rules with sensitivity classification
//! - Score overrides by executable name
//! - Regex patterns for matching complex command strings

use crate::types::*;
use std::path::{Path, PathBuf};

/// Parsed custom rule configuration.
#[derive(Debug, Clone, Default)]
pub struct RuleConfig {
    /// Commands that are always safe (exact match on executable name).
    pub allow: Vec<AllowRule>,
    /// Commands/patterns that are always blocked.
    pub block: Vec<BlockRule>,
    /// Custom command rules (extend the built-in 157 rules).
    pub commands: Vec<CustomCommandRule>,
    /// Custom path sensitivity rules.
    pub paths: Vec<CustomPathRule>,
    /// Score overrides by executable name.
    pub overrides: Vec<ScoreOverride>,
}

#[derive(Debug, Clone)]
pub struct AllowRule {
    /// Executable name (e.g., "make") or glob (e.g., "npm *")
    pub pattern: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct BlockRule {
    /// Executable name, glob, or regex (prefixed with "regex:")
    pub pattern: String,
    pub reason: String,
    pub mitre: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CustomCommandRule {
    pub name: String,
    pub intent: String,
    pub base_weight: u8,
    pub reversibility: String,
    pub mitre: Option<String>,
    pub dangerous_flags: Vec<CustomFlagRule>,
}

#[derive(Debug, Clone)]
pub struct CustomFlagRule {
    pub flags: Vec<String>,
    pub modifier: i8,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct CustomPathRule {
    pub pattern: String,
    pub sensitivity: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ScoreOverride {
    pub command: String,
    pub score: u8,
    pub reason: Option<String>,
}

impl RuleConfig {
    /// Load from a TOML file path.
    pub fn from_file(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        Self::from_toml(&content)
    }

    /// Parse from TOML string.
    pub fn from_toml(content: &str) -> Option<Self> {
        let table: toml::Table = content.parse().ok()?;
        let mut config = RuleConfig::default();

        // Parse allow list
        if let Some(arr) = table.get("allow").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    config.allow.push(AllowRule {
                        pattern: s.to_string(),
                        reason: "Allowed by project rules".to_string(),
                    });
                } else if let Some(tbl) = item.as_table() {
                    let pattern = tbl
                        .get("pattern")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let reason = tbl
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Allowed by project rules")
                        .to_string();
                    if !pattern.is_empty() {
                        config.allow.push(AllowRule { pattern, reason });
                    }
                }
            }
        }

        // Parse block list
        if let Some(arr) = table.get("block").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    config.block.push(BlockRule {
                        pattern: s.to_string(),
                        reason: "Blocked by project rules".to_string(),
                        mitre: None,
                    });
                } else if let Some(tbl) = item.as_table() {
                    let pattern = tbl
                        .get("pattern")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let reason = tbl
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Blocked by project rules")
                        .to_string();
                    let mitre = tbl.get("mitre").and_then(|v| v.as_str()).map(String::from);
                    if !pattern.is_empty() {
                        config.block.push(BlockRule {
                            pattern,
                            reason,
                            mitre,
                        });
                    }
                }
            }
        }

        // Parse custom command rules
        if let Some(arr) = table.get("commands").and_then(|v| v.as_array()) {
            for item in arr {
                let Some(tbl) = item.as_table() else {
                    continue;
                };
                let name = tbl
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                let intent = tbl
                    .get("intent")
                    .and_then(|v| v.as_str())
                    .unwrap_or("execute")
                    .to_string();
                let base_weight = tbl
                    .get("base_weight")
                    .and_then(|v| v.as_integer())
                    .map(|v| v.clamp(0, 100) as u8)
                    .unwrap_or(50);
                let reversibility = tbl
                    .get("reversibility")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hard_to_reverse")
                    .to_string();
                let mitre = tbl.get("mitre").and_then(|v| v.as_str()).map(String::from);

                let mut dangerous_flags = vec![];
                if let Some(flags_arr) = tbl.get("dangerous_flags").and_then(|v| v.as_array()) {
                    for flag_item in flags_arr {
                        let Some(flag_tbl) = flag_item.as_table() else {
                            continue;
                        };
                        let flags: Vec<String> = flag_tbl
                            .get("flags")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let modifier = flag_tbl
                            .get("modifier")
                            .and_then(|v| v.as_integer())
                            .map(|v| v.clamp(-100, 100) as i8)
                            .unwrap_or(10);
                        let description = flag_tbl
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if !flags.is_empty() {
                            dangerous_flags.push(CustomFlagRule {
                                flags,
                                modifier,
                                description,
                            });
                        }
                    }
                }

                config.commands.push(CustomCommandRule {
                    name,
                    intent,
                    base_weight,
                    reversibility,
                    mitre,
                    dangerous_flags,
                });
            }
        }

        // Parse custom path rules
        if let Some(arr) = table.get("paths").and_then(|v| v.as_array()) {
            for item in arr {
                let Some(tbl) = item.as_table() else {
                    continue;
                };
                let pattern = tbl
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if pattern.is_empty() {
                    continue;
                }
                let sensitivity = tbl
                    .get("sensitivity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("normal")
                    .to_string();
                let description = tbl
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Custom path rule")
                    .to_string();
                config.paths.push(CustomPathRule {
                    pattern,
                    sensitivity,
                    description,
                });
            }
        }

        // Parse score overrides
        if let Some(arr) = table.get("overrides").and_then(|v| v.as_array()) {
            for item in arr {
                let Some(tbl) = item.as_table() else {
                    continue;
                };
                let command = tbl
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if command.is_empty() {
                    continue;
                }
                let score = tbl
                    .get("score")
                    .and_then(|v| v.as_integer())
                    .map(|v| v.clamp(0, 100) as u8)
                    .unwrap_or(0);
                let reason = tbl.get("reason").and_then(|v| v.as_str()).map(String::from);
                config.overrides.push(ScoreOverride {
                    command,
                    score,
                    reason,
                });
            }
        }

        Some(config)
    }

    /// Auto-discover `.sh-guard.toml` from project root or cwd.
    pub fn discover(ctx: Option<&ClassifyContext>) -> Option<Self> {
        let search_paths: Vec<PathBuf> = [
            ctx.and_then(|c| c.project_root.as_ref())
                .map(|p| Path::new(p).join(".sh-guard.toml")),
            ctx.and_then(|c| c.cwd.as_ref())
                .map(|p| Path::new(p).join(".sh-guard.toml")),
            dirs().map(|h| h.join(".config/sh-guard/rules.toml")),
        ]
        .into_iter()
        .flatten()
        .collect();

        for path in search_paths {
            if path.exists() {
                return Self::from_file(&path);
            }
        }
        None
    }

    /// Check if a command matches any allow rule.
    pub fn is_allowed(&self, command: &str, executable: Option<&str>) -> Option<&AllowRule> {
        let exec = executable.unwrap_or("");
        self.allow.iter().find(|rule| {
            exec == rule.pattern
                || glob_match(&rule.pattern, command)
                || glob_match(&rule.pattern, exec)
        })
    }

    /// Check if a command matches any block rule.
    pub fn is_blocked(&self, command: &str, executable: Option<&str>) -> Option<&BlockRule> {
        let exec = executable.unwrap_or("");
        self.block.iter().find(|rule| {
            if rule.pattern.starts_with("regex:") {
                let pattern = &rule.pattern[6..];
                regex_match(pattern, command)
            } else {
                exec == rule.pattern
                    || glob_match(&rule.pattern, command)
                    || glob_match(&rule.pattern, exec)
            }
        })
    }

    /// Look up a custom command rule.
    pub fn lookup_command(&self, executable: &str) -> Option<&CustomCommandRule> {
        let base = executable.rsplit('/').next().unwrap_or(executable);
        self.commands.iter().find(|r| r.name == base)
    }

    /// Check if a path matches any custom path rule.
    pub fn check_path(&self, path: &str) -> Option<&CustomPathRule> {
        self.paths
            .iter()
            .find(|rule| glob_match(&rule.pattern, path))
    }

    /// Get score override for an executable.
    pub fn get_override(&self, executable: &str) -> Option<&ScoreOverride> {
        let base = executable.rsplit('/').next().unwrap_or(executable);
        self.overrides.iter().find(|o| o.command == base)
    }
}

fn dirs() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let (prefix, suffix) = (parts[0], parts[1]);
            text.starts_with(prefix) && text.ends_with(suffix)
        } else {
            text.contains(pattern.trim_matches('*'))
        }
    } else {
        text == pattern
    }
}

fn regex_match(pattern: &str, text: &str) -> bool {
    // Lightweight regex support for common patterns without pulling in the regex crate.
    // Supports: literal substrings, .* (any), ^ (start), $ (end)
    let pattern = pattern.trim_start_matches('^').trim_end_matches('$');

    if pattern.contains(".*") {
        // Split on .* and check all parts appear in order
        let parts: Vec<&str> = pattern.split(".*").collect();
        let mut remaining = text;
        for part in &parts {
            if part.is_empty() {
                continue;
            }
            if let Some(pos) = remaining.find(part) {
                remaining = &remaining[pos + part.len()..];
            } else {
                return false;
            }
        }
        true
    } else {
        text.contains(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_allow_block() {
        let toml = r#"
allow = [
    "make",
    { pattern = "npm run *", reason = "Project scripts are safe" },
    "cargo test",
]

block = [
    { pattern = "rm -rf /", reason = "Never delete root", mitre = "T1485" },
    "curl * | bash",
    { pattern = "regex:docker.*--privileged", reason = "No privileged containers" },
]
"#;
        let config = RuleConfig::from_toml(toml).unwrap();
        assert_eq!(config.allow.len(), 3);
        assert_eq!(config.block.len(), 3);

        assert!(config.is_allowed("make build", Some("make")).is_some());
        assert!(config.is_allowed("npm run dev", Some("npm")).is_some());
        assert!(config.is_allowed("rm -rf /", Some("rm")).is_none());

        assert!(config.is_blocked("rm -rf /", Some("rm")).is_some());
        assert!(config
            .is_blocked("docker run --privileged ubuntu", Some("docker"))
            .is_some());
    }

    #[test]
    fn test_parse_custom_commands() {
        let toml = r#"
[[commands]]
name = "deploy"
intent = "execute"
base_weight = 70
reversibility = "hard_to_reverse"
mitre = "T1072"

[[commands.dangerous_flags]]
flags = ["--production"]
modifier = 20
description = "Deploying to production"

[[commands.dangerous_flags]]
flags = ["--force", "--no-backup"]
modifier = 30
description = "Force deploy without backup"
"#;
        let config = RuleConfig::from_toml(toml).unwrap();
        assert_eq!(config.commands.len(), 1);
        assert_eq!(config.commands[0].name, "deploy");
        assert_eq!(config.commands[0].dangerous_flags.len(), 2);
    }

    #[test]
    fn test_parse_overrides() {
        let toml = r#"
[[overrides]]
command = "terraform"
score = 80
reason = "Terraform changes infrastructure — always review"
"#;
        let config = RuleConfig::from_toml(toml).unwrap();
        assert_eq!(config.overrides.len(), 1);
        let o = config.get_override("terraform").unwrap();
        assert_eq!(o.score, 80);
    }

    #[test]
    fn test_empty_config() {
        let config = RuleConfig::from_toml("").unwrap();
        assert!(config.allow.is_empty());
        assert!(config.block.is_empty());
    }
}
