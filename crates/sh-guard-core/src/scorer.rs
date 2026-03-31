use crate::context;
use crate::rules::injection;
use crate::rules::zsh;
use crate::types::*;

/// Score a single command analysis.
/// Layer 1: BASE = intent_weight + target_scope + sensitivity
/// Layer 2: ADJUSTED = BASE + flag_modifiers + reversibility + context_adjustment
pub fn score_command(analysis: &mut CommandAnalysis, ctx: Option<&ClassifyContext>) {
    let shell = ctx.map(|c| c.shell).unwrap_or(Shell::Bash);

    // Layer 1: Base score from intent
    let intent_weight: i16 = analysis
        .intent
        .iter()
        .map(|i| i.weight() as i16)
        .max()
        .unwrap_or(0);

    // Best (highest) target scope and sensitivity
    let scope_modifier: i16 = analysis
        .targets
        .iter()
        .map(|t| t.scope.modifier())
        .max()
        .unwrap_or(0);

    let sensitivity_modifier: i16 = analysis
        .targets
        .iter()
        .map(|t| t.sensitivity.modifier())
        .max()
        .unwrap_or(0);

    let base = intent_weight + scope_modifier + sensitivity_modifier;

    // Layer 2: Adjustments
    let flag_modifier: i16 = analysis.flags.iter().map(|f| f.modifier as i16).sum();

    let reversibility_modifier = analysis.reversibility.modifier();

    // Context adjustment: use the highest-risk target path
    let ctx_adjustment: i16 = analysis
        .targets
        .iter()
        .filter_map(|t| t.path.as_ref())
        .map(|path| {
            let primary_intent = analysis.intent.first().copied().unwrap_or(Intent::Info);
            context::context_adjustment(path, &primary_intent, ctx)
        })
        .max()
        .unwrap_or_else(|| if ctx.is_some() { 0 } else { 5 }); // No context = +5

    // Injection pattern score bonus
    let injection_score: i16 = injection::detect_injections(&analysis.command, &analysis.command)
        .iter()
        .map(|(_, score, _, _)| *score as i16)
        .max()
        .unwrap_or(0);

    // Zsh rule score bonus
    let zsh_score: i16 = if shell == Shell::Zsh {
        zsh::detect_zsh_patterns(&analysis.command)
            .iter()
            .map(|(_, score, _, _)| *score as i16)
            .max()
            .unwrap_or(0)
    } else {
        0
    };

    // Combine: take the max of base-path and injection/zsh scores
    // (injection/zsh patterns can independently make a command dangerous)
    let structural_score = base + flag_modifier + reversibility_modifier + ctx_adjustment;
    let pattern_score = injection_score.max(zsh_score);

    // Final: max of structural analysis and pattern detection, but they also compound
    // If both are present, the command is more dangerous
    let combined = if structural_score > 20 && pattern_score > 20 {
        // Both significant -- take max and add a portion of the other
        structural_score.max(pattern_score) + (structural_score.min(pattern_score) / 4)
    } else {
        structural_score.max(pattern_score)
    };

    analysis.score = combined.clamp(0, 100) as u8;
}

/// Generate a human-readable reason string.
pub fn generate_reason(analysis: &CommandAnalysis) -> String {
    let mut parts = vec![];

    // Describe intent
    let intent_desc = match analysis.intent.first() {
        Some(Intent::Info) => "Information command",
        Some(Intent::Search) => "Search operation",
        Some(Intent::Read) => "File read",
        Some(Intent::Write) => "File write",
        Some(Intent::Delete) => "File deletion",
        Some(Intent::Execute) => "Code execution",
        Some(Intent::Network) => "Network operation",
        Some(Intent::ProcessControl) => "Process control",
        Some(Intent::Privilege) => "Privilege operation",
        Some(Intent::PackageInstall) => "Package installation",
        Some(Intent::GitMutation) => "Git mutation",
        Some(Intent::EnvModify) => "Environment modification",
        None => "Unknown operation",
    };
    parts.push(intent_desc.to_string());

    // Describe notable targets
    for target in &analysis.targets {
        if let Some(path) = &target.path {
            match target.scope {
                TargetScope::Root => parts.push("targeting filesystem root".to_string()),
                TargetScope::Home => parts.push("targeting home directory".to_string()),
                TargetScope::System => {
                    parts.push(format!("targeting system path {}", path))
                }
                _ => {}
            }
            match target.sensitivity {
                Sensitivity::Secrets => parts.push(format!("accessing secrets ({})", path)),
                Sensitivity::System => parts.push(format!("accessing system file ({})", path)),
                Sensitivity::Protected => {
                    parts.push(format!("accessing protected path ({})", path))
                }
                _ => {}
            }
        }
    }

    // Describe risk factors
    for rf in &analysis.risk_factors {
        let desc = match rf {
            RiskFactor::RecursiveDelete => "recursive deletion",
            RiskFactor::ForceFlag => "force flag",
            RiskFactor::BroadScope => "broad scope",
            RiskFactor::NetworkExfiltration => "potential data exfiltration",
            RiskFactor::PipeToExecution => "output piped to execution",
            RiskFactor::UntrustedExecution => "execution of untrusted content",
            RiskFactor::PrivilegeEscalation => "privilege escalation",
            RiskFactor::GitHistoryDestruction => "git history destruction",
            RiskFactor::EscapesProjectBoundary => "escapes project boundary",
            RiskFactor::ShellInjection => "shell injection pattern",
            RiskFactor::ZshModuleLoading => "zsh module loading",
            RiskFactor::ObfuscatedCommand => "obfuscated command",
            _ => continue,
        };
        parts.push(desc.to_string());
    }

    if parts.len() == 1 {
        parts[0].clone()
    } else {
        let (first, rest) = parts.split_first().unwrap();
        format!("{}: {}", first, rest.join(", "))
    }
}
