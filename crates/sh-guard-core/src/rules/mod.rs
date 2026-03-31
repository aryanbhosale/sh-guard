use crate::types::*;
use std::path::Path;

pub mod commands;
pub mod gtfobins;
pub mod injection;
pub mod network;
pub mod paths;
pub mod zsh;

/// A rule defining the risk profile of a known command.
#[derive(Debug, Clone)]
pub struct CommandRule {
    pub name: &'static str,
    pub intent: Intent,
    pub base_weight: u8,
    pub reversibility: Reversibility,
    pub capabilities: &'static [BinaryCapability],
    pub dangerous_flags: &'static [FlagRule],
    pub mitre: Option<&'static str>,
}

/// A rule for a dangerous flag combination.
#[derive(Debug, Clone)]
pub struct FlagRule {
    pub flags: &'static [&'static str],
    pub modifier: i8,
    pub risk_factor: RiskFactor,
    pub description: &'static str,
}

/// Look up a command rule by executable name.
pub fn lookup_command(name: &str) -> Option<&'static CommandRule> {
    // Strip path prefix: /usr/bin/ls -> ls
    let base = name.rsplit('/').next().unwrap_or(name);
    commands::COMMAND_RULES.iter().find(|r| r.name == base)
}

// ========================================================
// RuleSet: aggregated access to all rule tables
// ========================================================

/// A user-defined command rule loaded from TOML configuration.
#[derive(Debug, Clone)]
pub struct UserCommandRule {
    pub name: String,
    pub intent: Intent,
    pub base_weight: u8,
    pub reversibility: Reversibility,
}

/// Aggregated access to all rule tables, including optional user-defined rules.
pub struct RuleSet {
    pub user_commands: Vec<UserCommandRule>,
    pub user_paths: Vec<paths::PathRule>,
}

impl RuleSet {
    /// Create a RuleSet with only built-in rules (no user rules).
    pub fn builtin() -> Self {
        RuleSet {
            user_commands: vec![],
            user_paths: vec![],
        }
    }

    /// Load user rules from a TOML file, merging with built-in rules.
    /// User rules can only ADD commands/paths, not override built-in ones.
    pub fn with_user_rules(toml_path: &Path) -> Self {
        let mut ruleset = Self::builtin();
        if let Ok(content) = std::fs::read_to_string(toml_path) {
            // Parse TOML — best effort, ignore parse errors
            if let Ok(table) = content.parse::<toml::Table>() {
                Self::load_user_commands(&mut ruleset, &table);
                Self::load_user_paths(&mut ruleset, &table);
            }
        }
        ruleset
    }

    fn load_user_commands(ruleset: &mut RuleSet, table: &toml::Table) {
        let Some(cmds) = table.get("commands").and_then(|v| v.as_array()) else {
            return;
        };
        for cmd in cmds {
            let Some(tbl) = cmd.as_table() else { continue };
            let name = tbl
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() || lookup_command(&name).is_some() {
                continue; // Skip empty or built-in override attempts
            }
            let intent = parse_intent(tbl.get("intent").and_then(|v| v.as_str()));
            let base_weight = tbl
                .get("base_weight")
                .and_then(|v| v.as_integer())
                .map(|v| v.clamp(0, 100) as u8)
                .unwrap_or(intent.weight());
            let reversibility =
                parse_reversibility(tbl.get("reversibility").and_then(|v| v.as_str()));
            ruleset.user_commands.push(UserCommandRule {
                name,
                intent,
                base_weight,
                reversibility,
            });
        }
    }

    fn load_user_paths(ruleset: &mut RuleSet, table: &toml::Table) {
        let Some(path_arr) = table.get("paths").and_then(|v| v.as_array()) else {
            return;
        };
        for entry in path_arr {
            let Some(tbl) = entry.as_table() else { continue };
            let pattern = tbl
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if pattern.is_empty() {
                continue;
            }
            let sensitivity = match tbl.get("sensitivity").and_then(|v| v.as_str()) {
                Some("secrets") => Sensitivity::Secrets,
                Some("system") => Sensitivity::System,
                Some("config") => Sensitivity::Config,
                Some("protected") => Sensitivity::Protected,
                _ => Sensitivity::Normal,
            };
            let description = tbl
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("User-defined path rule");
            // PathRule uses &'static str, so we leak the strings to get 'static lifetime.
            // This is acceptable for user rules loaded once at startup.
            let pattern_leaked: &'static str = Box::leak(pattern.to_string().into_boxed_str());
            let desc_leaked: &'static str =
                Box::leak(description.to_string().into_boxed_str());
            ruleset.user_paths.push(paths::PathRule {
                pattern: pattern_leaked,
                sensitivity,
                description: desc_leaked,
            });
        }
    }

    /// Look up a command in user rules (returns None if not found;
    /// caller should fall back to built-in lookup).
    pub fn lookup_user_command(&self, name: &str) -> Option<&UserCommandRule> {
        let base = name.rsplit('/').next().unwrap_or(name);
        self.user_commands.iter().find(|r| r.name == base)
    }
}

fn parse_intent(s: Option<&str>) -> Intent {
    match s {
        Some("read") => Intent::Read,
        Some("write") => Intent::Write,
        Some("delete") => Intent::Delete,
        Some("execute") => Intent::Execute,
        Some("network") => Intent::Network,
        Some("privilege") => Intent::Privilege,
        Some("search") => Intent::Search,
        Some("info") => Intent::Info,
        Some("package_install") => Intent::PackageInstall,
        Some("git_mutation") => Intent::GitMutation,
        Some("env_modify") => Intent::EnvModify,
        Some("process_control") => Intent::ProcessControl,
        _ => Intent::Execute, // default to high-weight intent
    }
}

fn parse_reversibility(s: Option<&str>) -> Reversibility {
    match s {
        Some("reversible") => Reversibility::Reversible,
        Some("hard_to_reverse") => Reversibility::HardToReverse,
        Some("irreversible") => Reversibility::Irreversible,
        _ => Reversibility::HardToReverse,
    }
}
