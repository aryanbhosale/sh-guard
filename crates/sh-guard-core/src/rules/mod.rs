use crate::types::*;

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
