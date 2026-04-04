use crate::types::RiskFactor;

#[derive(Debug, Clone)]
pub struct ZshRule {
    pub name: &'static str,
    pub detect_fn: fn(&str) -> bool,
    pub score: u8,
    pub risk_factor: RiskFactor,
    pub description: &'static str,
}

pub static ZSH_RULES: &[ZshRule] = &[
    ZshRule {
        name: "zmodload",
        detect_fn: |cmd| cmd.contains("zmodload"),
        score: 55,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "Loading zsh modules (can enable dangerous builtins)",
    },
    ZshRule {
        name: "zsh_system_module",
        detect_fn: |cmd| cmd.contains("zsh/system"),
        score: 60,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "zsh/system module (sysopen, sysread, syswrite)",
    },
    ZshRule {
        name: "zsh_zpty_module",
        detect_fn: |cmd| cmd.contains("zsh/zpty") || cmd.contains("zpty"),
        score: 55,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "zsh/zpty module (pseudo-terminal execution)",
    },
    ZshRule {
        name: "zsh_net_tcp",
        detect_fn: |cmd| cmd.contains("zsh/net/tcp") || cmd.contains("ztcp"),
        score: 55,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "zsh TCP networking module",
    },
    ZshRule {
        name: "zsh_net_socket",
        detect_fn: |cmd| cmd.contains("zsh/net/socket") || cmd.contains("zsocket"),
        score: 55,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "zsh socket networking module",
    },
    ZshRule {
        name: "zsh_mapfile",
        detect_fn: |cmd| cmd.contains("zsh/mapfile") || cmd.contains("mapfile"),
        score: 45,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "zsh/mapfile (invisible file I/O via array)",
    },
    ZshRule {
        name: "zsh_files_module",
        detect_fn: |cmd| {
            cmd.contains("zsh/files")
                || cmd.contains("zf_rm")
                || cmd.contains("zf_mv")
                || cmd.contains("zf_chmod")
                || cmd.contains("zf_chown")
                || cmd.contains("zf_mkdir")
                || cmd.contains("zf_rmdir")
                || cmd.contains("zf_ln")
                || cmd.contains("zf_chgrp")
        },
        score: 45,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "zsh/files builtins (file operations bypassing PATH)",
    },
    ZshRule {
        name: "emulate_eval",
        detect_fn: |cmd| cmd.contains("emulate") && cmd.contains("-c"),
        score: 50,
        risk_factor: RiskFactor::CommandExecution,
        description: "emulate -c (eval equivalent in zsh)",
    },
    ZshRule {
        name: "sysopen",
        detect_fn: |cmd| cmd.contains("sysopen"),
        score: 50,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "sysopen (direct file descriptor access)",
    },
    ZshRule {
        name: "sysread_syswrite",
        detect_fn: |cmd| {
            cmd.contains("sysread") || cmd.contains("syswrite") || cmd.contains("sysseek")
        },
        score: 50,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "sysread/syswrite/sysseek (raw I/O)",
    },
    ZshRule {
        name: "glob_qualifier_exec",
        detect_fn: |cmd| {
            // (e:...) or (+...) glob qualifiers with execution
            cmd.contains("(e:") || cmd.contains("(+")
        },
        score: 55,
        risk_factor: RiskFactor::ZshGlobExecution,
        description: "Zsh glob qualifier with code execution",
    },
    ZshRule {
        name: "equals_expansion",
        detect_fn: |cmd| {
            // =cmd at word start: zsh expands =foo to /path/to/foo
            cmd.split_whitespace().any(|word| {
                word.starts_with('=')
                    && word.len() > 1
                    && word[1..].chars().next().is_some_and(|c| c.is_alphabetic())
            })
        },
        score: 40,
        risk_factor: RiskFactor::ZshGlobExecution,
        description: "Zsh equals expansion (=cmd → /path/to/cmd)",
    },
    ZshRule {
        name: "always_block",
        detect_fn: |cmd| cmd.contains("always"),
        score: 30,
        risk_factor: RiskFactor::ShellInjection,
        description: "Zsh always block (try/always construct)",
    },
    ZshRule {
        name: "precommand_noglob",
        detect_fn: |cmd| cmd.starts_with("noglob ") || cmd.contains(" noglob "),
        score: 20,
        risk_factor: RiskFactor::ShellInjection,
        description: "Zsh noglob precommand modifier",
    },
    ZshRule {
        name: "zsh_autoload",
        detect_fn: |cmd| cmd.contains("autoload") && cmd.contains("-U"),
        score: 25,
        risk_factor: RiskFactor::ZshModuleLoading,
        description: "Zsh autoload -U (loading functions)",
    },
];

/// Check a command against zsh-specific rules.
pub fn detect_zsh_patterns(command: &str) -> Vec<(&'static str, u8, RiskFactor, &'static str)> {
    ZSH_RULES
        .iter()
        .filter(|r| (r.detect_fn)(command))
        .map(|r| (r.name, r.score, r.risk_factor, r.description))
        .collect()
}
