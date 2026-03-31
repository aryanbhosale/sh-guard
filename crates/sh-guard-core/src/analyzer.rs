use crate::context;
use crate::parser::*;
use crate::rules;
use crate::rules::gtfobins;
use crate::rules::injection;
use crate::rules::zsh;
use crate::types::*;

/// Analyze parsed command segments into CommandAnalysis structs.
pub fn analyze(parsed: &ParsedCommand, ctx: Option<&ClassifyContext>) -> Vec<CommandAnalysis> {
    let shell = ctx.map(|c| c.shell).unwrap_or(Shell::Bash);

    parsed
        .segments
        .iter()
        .map(|segment| analyze_segment(segment, ctx, shell, &parsed.parse_warnings))
        .collect()
}

fn analyze_segment(
    segment: &CommandSegment,
    ctx: Option<&ClassifyContext>,
    shell: Shell,
    warnings: &[ParseWarning],
) -> CommandAnalysis {
    let executable = segment.executable.as_deref();
    let exec_base = executable.map(|e| e.rsplit('/').next().unwrap_or(e));

    // 1. Look up command rule
    let cmd_rule = executable.and_then(rules::lookup_command);

    // 2. Determine intent
    let intent = if let Some(rule) = cmd_rule {
        vec![rule.intent]
    } else {
        // Unknown command -- default to Execute (conservative)
        vec![Intent::Execute]
    };

    // 3. Determine reversibility
    let reversibility = cmd_rule
        .map(|r| r.reversibility)
        .unwrap_or(Reversibility::HardToReverse);

    // 4. Look up GTFOBins capabilities
    let capabilities: Vec<BinaryCapability> = exec_base
        .map(|name| gtfobins::lookup_capabilities(name).to_vec())
        .unwrap_or_default();

    // 5. Analyze flags -- check for dangerous flag combinations
    let mut flags = vec![];
    if let Some(rule) = cmd_rule {
        for flag_rule in rule.dangerous_flags {
            if flag_matches(&segment.raw, flag_rule) {
                flags.push(FlagAnalysis {
                    flag: flag_rule.flags[0].to_string(),
                    modifier: flag_rule.modifier,
                    risk_factor: flag_rule.risk_factor,
                    description: flag_rule.description.to_string(),
                });
            }
        }
    }

    // 6. Determine targets (from args that look like paths)
    let targets = extract_targets(segment, ctx);

    // 7. Collect risk factors from flags, injection patterns, zsh rules
    let mut risk_factors: Vec<RiskFactor> = flags.iter().map(|f| f.risk_factor).collect();

    // Check injection patterns on the raw command text
    let injections = injection::detect_injections(&segment.raw, &segment.raw);
    for (_, _, rf, _) in &injections {
        if !risk_factors.contains(rf) {
            risk_factors.push(*rf);
        }
    }

    // Check zsh rules if shell is Zsh
    if shell == Shell::Zsh {
        let zsh_matches = zsh::detect_zsh_patterns(&segment.raw);
        for (_, _, rf, _) in &zsh_matches {
            if !risk_factors.contains(rf) {
                risk_factors.push(*rf);
            }
        }
    }

    // Check parse warnings
    for warning in warnings {
        match warning {
            ParseWarning::ControlCharacters(_) => {
                if !risk_factors.contains(&RiskFactor::ShellInjection) {
                    risk_factors.push(RiskFactor::ShellInjection);
                }
            }
            ParseWarning::UnicodeWhitespace(_) => {
                if !risk_factors.contains(&RiskFactor::ShellInjection) {
                    risk_factors.push(RiskFactor::ShellInjection);
                }
            }
            ParseWarning::AnsiCQuoting => {
                if !risk_factors.contains(&RiskFactor::ObfuscatedCommand) {
                    risk_factors.push(RiskFactor::ObfuscatedCommand);
                }
            }
            _ => {}
        }
    }

    CommandAnalysis {
        command: segment.raw.clone(),
        executable: executable.map(String::from),
        intent,
        targets,
        flags,
        score: 0, // Scorer fills this in
        risk_factors,
        reversibility,
        capabilities,
    }
}

/// Check if a command's raw text contains the flag pattern.
fn flag_matches(raw: &str, flag_rule: &rules::FlagRule) -> bool {
    flag_rule.flags.iter().any(|pattern| {
        // Split pattern into parts and check all are present
        let parts: Vec<&str> = pattern.split_whitespace().collect();
        parts
            .iter()
            .all(|part| raw.split_whitespace().any(|word| word == *part || word.starts_with(part)))
    })
}

/// Extract targets from command arguments.
fn extract_targets(segment: &CommandSegment, ctx: Option<&ClassifyContext>) -> Vec<Target> {
    let mut targets = vec![];

    for arg in &segment.args {
        // Skip flags (start with -)
        if arg.value.starts_with('-') {
            continue;
        }

        // Check if this looks like a path
        let val = &arg.value;
        if val.starts_with('/')
            || val.starts_with('.')
            || val.starts_with('~')
            || val.contains('/')
            || val == "*"
        {
            let scope = context::resolve_scope(val, ctx);
            let sensitivity = context::resolve_sensitivity(val, ctx);
            targets.push(Target {
                path: Some(val.clone()),
                scope,
                sensitivity,
            });
        }
    }

    // Check redirection targets too
    for redir in &segment.redirections {
        if !redir.target.is_empty() {
            let scope = context::resolve_scope(&redir.target, ctx);
            let sensitivity = context::resolve_sensitivity(&redir.target, ctx);
            targets.push(Target {
                path: Some(redir.target.clone()),
                scope,
                sensitivity,
            });
        }
    }

    // If no targets found, add a None target
    if targets.is_empty() {
        targets.push(Target {
            path: None,
            scope: TargetScope::None,
            sensitivity: Sensitivity::Normal,
        });
    }

    targets
}
