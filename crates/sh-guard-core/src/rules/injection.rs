use crate::types::RiskFactor;

#[derive(Debug, Clone)]
pub struct InjectionPattern {
    pub name: &'static str,
    pub detect_fn: fn(&str, &str) -> bool, // (unquoted_text, raw_text) -> matched
    pub score: u8,
    pub risk_factor: RiskFactor,
    pub description: &'static str,
}

pub static INJECTION_PATTERNS: &[InjectionPattern] = &[
    InjectionPattern {
        name: "command_substitution_dollar",
        detect_fn: |unquoted, _raw| unquoted.contains("$("),
        score: 40,
        risk_factor: RiskFactor::CommandSubstitution,
        description: "$() command substitution",
    },
    InjectionPattern {
        name: "command_substitution_backtick",
        detect_fn: |unquoted, _raw| unquoted.contains('`'),
        score: 40,
        risk_factor: RiskFactor::CommandSubstitution,
        description: "Backtick command substitution",
    },
    InjectionPattern {
        name: "process_substitution_in",
        detect_fn: |unquoted, _raw| unquoted.contains("<("),
        score: 45,
        risk_factor: RiskFactor::ProcessSubstitution,
        description: "<() process substitution",
    },
    InjectionPattern {
        name: "process_substitution_out",
        detect_fn: |unquoted, _raw| unquoted.contains(">("),
        score: 45,
        risk_factor: RiskFactor::ProcessSubstitution,
        description: ">() process substitution",
    },
    InjectionPattern {
        name: "parameter_expansion",
        detect_fn: |unquoted, _raw| unquoted.contains("${"),
        score: 35,
        risk_factor: RiskFactor::ShellInjection,
        description: "${} parameter expansion",
    },
    InjectionPattern {
        name: "ifs_injection",
        detect_fn: |unquoted, _raw| unquoted.contains("$IFS") || unquoted.contains("${IFS"),
        score: 50,
        risk_factor: RiskFactor::ShellInjection,
        description: "IFS variable manipulation",
    },
    InjectionPattern {
        name: "arithmetic_expansion",
        detect_fn: |unquoted, _raw| unquoted.contains("$(("),
        score: 30,
        risk_factor: RiskFactor::ShellInjection,
        description: "Arithmetic expansion",
    },
    InjectionPattern {
        name: "unicode_whitespace",
        detect_fn: |_unquoted, raw| {
            raw.chars()
                .any(|c| c.is_whitespace() && !matches!(c, ' ' | '\t' | '\n' | '\r'))
        },
        score: 45,
        risk_factor: RiskFactor::ShellInjection,
        description: "Non-ASCII whitespace (obfuscation)",
    },
    InjectionPattern {
        name: "control_characters",
        detect_fn: |_unquoted, raw| {
            raw.bytes()
                .any(|b| matches!(b, 0x00..=0x08 | 0x0E..=0x1F | 0x7F))
        },
        score: 45,
        risk_factor: RiskFactor::ShellInjection,
        description: "Control characters in command",
    },
    InjectionPattern {
        name: "carriage_return",
        detect_fn: |_unquoted, raw| raw.contains('\r'),
        score: 40,
        risk_factor: RiskFactor::ShellInjection,
        description: "Carriage return (misparsing risk)",
    },
    InjectionPattern {
        name: "ansi_c_quoting",
        detect_fn: |_unquoted, raw| raw.contains("$'") || raw.contains("$\""),
        score: 35,
        risk_factor: RiskFactor::ObfuscatedCommand,
        description: "ANSI-C quoting (can encode arbitrary bytes)",
    },
    InjectionPattern {
        name: "escaped_semicolon",
        detect_fn: |_unquoted, raw| raw.contains("\\;"),
        score: 25,
        risk_factor: RiskFactor::ShellInjection,
        description: "Escaped semicolon",
    },
    InjectionPattern {
        name: "escaped_pipe",
        detect_fn: |_unquoted, raw| raw.contains("\\|"),
        score: 25,
        risk_factor: RiskFactor::ShellInjection,
        description: "Escaped pipe",
    },
    InjectionPattern {
        name: "escaped_ampersand",
        detect_fn: |_unquoted, raw| raw.contains("\\&"),
        score: 25,
        risk_factor: RiskFactor::ShellInjection,
        description: "Escaped ampersand",
    },
    InjectionPattern {
        name: "brace_expansion",
        detect_fn: |unquoted, _raw| {
            // Must contain {, at least one comma, and }
            if let Some(start) = unquoted.find('{') {
                if let Some(end) = unquoted[start..].find('}') {
                    return unquoted[start..start + end].contains(',');
                }
            }
            false
        },
        score: 20,
        risk_factor: RiskFactor::ShellInjection,
        description: "Brace expansion",
    },
    InjectionPattern {
        name: "proc_environ_access",
        detect_fn: |_unquoted, raw| {
            raw.contains("/proc/self/environ") || raw.contains("/proc/") && raw.contains("/environ")
        },
        score: 50,
        risk_factor: RiskFactor::SecretsExposure,
        description: "Process environment access",
    },
    InjectionPattern {
        name: "dev_tcp_udp",
        detect_fn: |_unquoted, raw| raw.contains("/dev/tcp/") || raw.contains("/dev/udp/"),
        score: 55,
        risk_factor: RiskFactor::NetworkExfiltration,
        description: "Bash /dev/tcp or /dev/udp network access",
    },
    InjectionPattern {
        name: "base64_pipe",
        detect_fn: |_unquoted, raw| {
            (raw.contains("base64") || raw.contains("b64"))
                && (raw.contains("|") || raw.contains(">"))
        },
        score: 30,
        risk_factor: RiskFactor::ObfuscatedCommand,
        description: "Base64 encoding in pipeline (potential obfuscation)",
    },
    InjectionPattern {
        name: "eval_usage",
        detect_fn: |unquoted, _raw| {
            unquoted.starts_with("eval ")
                || unquoted.contains(" eval ")
                || unquoted.starts_with("source ")
                || unquoted.contains(" source ")
        },
        score: 50,
        risk_factor: RiskFactor::CommandExecution,
        description: "eval/source command usage",
    },
    InjectionPattern {
        name: "dot_sourcing",
        detect_fn: |unquoted, _raw| {
            // Detect ". /path" (dot-sourcing) at start or in middle.
            // Must be followed by a space and then a path starting with /
            // to avoid false positives on relative paths like "./script".
            unquoted.starts_with(". /") || unquoted.contains(" . /")
        },
        score: 50,
        risk_factor: RiskFactor::CommandExecution,
        description: "Dot-sourcing a script (. /path)",
    },
    InjectionPattern {
        name: "hex_escape_sequences",
        detect_fn: |_unquoted, raw| raw.contains("\\x") || raw.contains("\\u"),
        score: 35,
        risk_factor: RiskFactor::ObfuscatedCommand,
        description: "Hex/unicode escape sequences (obfuscation)",
    },
    InjectionPattern {
        name: "ld_preload",
        detect_fn: |_unquoted, raw| raw.contains("LD_PRELOAD") || raw.contains("LD_LIBRARY_PATH"),
        score: 55,
        risk_factor: RiskFactor::PathInjection,
        description: "LD_PRELOAD/LD_LIBRARY_PATH injection",
    },
    InjectionPattern {
        name: "path_injection",
        detect_fn: |_unquoted, raw| {
            raw.contains("PATH=") && !raw.contains("$PATH")
                || raw.contains("PATH=/tmp")
                || raw.contains("PATH=/var")
        },
        score: 50,
        risk_factor: RiskFactor::PathInjection,
        description: "PATH environment variable override",
    },
    InjectionPattern {
        name: "history_manipulation",
        detect_fn: |_unquoted, raw| {
            raw.contains("HISTFILE") || raw.contains(".bash_history") || raw.contains("HISTSIZE=0")
        },
        score: 40,
        risk_factor: RiskFactor::ShellInjection,
        description: "Shell history manipulation",
    },
    InjectionPattern {
        name: "null_byte",
        detect_fn: |_unquoted, raw| raw.bytes().any(|b| b == 0),
        score: 50,
        risk_factor: RiskFactor::ShellInjection,
        description: "Null byte injection",
    },
    InjectionPattern {
        name: "pipe_to_shell",
        detect_fn: |_unquoted, raw| {
            let lower = raw.to_lowercase();
            // With space after pipe
            lower.contains("| bash")
                || lower.contains("| sh")
                || lower.contains("| zsh")
                || lower.contains("| fish")
                || lower.contains("| ksh")
                || lower.contains("| csh")
                || lower.contains("| tcsh")
                || lower.contains("| dash")
                || lower.contains("| python")
                || lower.contains("| python3")
                || lower.contains("| perl")
                || lower.contains("| ruby")
                || lower.contains("| node")
                || lower.contains("| nodejs")
                // Without space after pipe
                || lower.contains("|bash")
                || lower.contains("|sh")
                || lower.contains("|zsh")
                || lower.contains("|fish")
                || lower.contains("|ksh")
                || lower.contains("|csh")
                || lower.contains("|tcsh")
                || lower.contains("|dash")
                || lower.contains("|python")
                || lower.contains("|python3")
                || lower.contains("|perl")
                || lower.contains("|ruby")
                || lower.contains("|node")
                || lower.contains("|nodejs")
        },
        score: 55,
        risk_factor: RiskFactor::PipeToExecution,
        description: "Output piped to shell or interpreter execution",
    },
];

/// Check a command against all injection patterns.
/// Returns list of (pattern_name, score, risk_factor, description) for matches.
pub fn detect_injections(
    unquoted: &str,
    raw: &str,
) -> Vec<(&'static str, u8, RiskFactor, &'static str)> {
    INJECTION_PATTERNS
        .iter()
        .filter(|p| (p.detect_fn)(unquoted, raw))
        .map(|p| (p.name, p.score, p.risk_factor, p.description))
        .collect()
}
