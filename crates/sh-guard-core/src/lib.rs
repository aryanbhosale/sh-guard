pub mod types;
pub use types::*;

pub(crate) mod parser;
#[doc(hidden)]
pub mod rules;
#[doc(hidden)]
pub mod context;
#[doc(hidden)]
pub mod analyzer;
#[doc(hidden)]
pub mod scorer;
#[doc(hidden)]
pub mod pipeline;

#[doc(hidden)]
pub mod test_internals {
    pub use crate::parser::*;
    pub use crate::rules;
    pub use crate::context;
    pub use crate::analyzer;
    pub use crate::scorer;
    pub use crate::pipeline;
}

/// Classify a shell command and return a rich analysis.
pub fn classify(command: &str, context: Option<&ClassifyContext>) -> AnalysisResult {
    let shell = context.map(|c| c.shell).unwrap_or(Shell::Bash);

    // 1. Parse
    let parsed = parser::parse(command, shell);

    // 2. Determine parse confidence
    let parse_confidence = if parsed
        .parse_warnings
        .iter()
        .any(|w| matches!(w, parser::ParseWarning::TreeSitterError(_)))
    {
        if parsed.segments.len() <= 1
            && parsed
                .segments
                .first()
                .map_or(true, |s| s.executable.is_none())
        {
            ParseConfidence::Fallback
        } else {
            ParseConfidence::Partial
        }
    } else {
        ParseConfidence::Full
    };

    // 3. Analyze
    let mut analyses = analyzer::analyze(&parsed, context);

    // 4. Score each segment
    for analysis in &mut analyses {
        scorer::score_command(analysis, context);
    }

    // 5. Pipeline analysis
    let pipeline_flow = pipeline::analyze_pipeline(&analyses, &parsed.chain_operators);

    // 6. Compute final score
    let segment_max = analyses.iter().map(|a| a.score).max().unwrap_or(0);
    let final_score = if let Some(ref pf) = pipeline_flow {
        pf.composite_score.max(segment_max)
    } else {
        segment_max
    };

    // Add parse confidence penalty
    let final_score = match parse_confidence {
        ParseConfidence::Fallback => (final_score as u16 + 10).min(100) as u8,
        ParseConfidence::Partial => (final_score as u16 + 5).min(100) as u8,
        ParseConfidence::Full => final_score,
    };

    let level = RiskLevel::from_score(final_score);
    let quick_decision = QuickDecision::from_level(level);

    // Collect all risk factors
    let mut all_risk_factors: Vec<RiskFactor> = analyses
        .iter()
        .flat_map(|a| a.risk_factors.iter().copied())
        .collect();
    all_risk_factors.sort_by_key(|r| format!("{:?}", r));
    all_risk_factors.dedup();

    // Collect MITRE mappings from matching command rules
    let mut mitre_mappings = vec![];
    for analysis in &analyses {
        if let Some(exec) = &analysis.executable {
            if let Some(rule) = rules::lookup_command(exec) {
                if let Some(mitre_id) = rule.mitre {
                    let mapping = MitreMapping {
                        technique_id: mitre_id.to_string(),
                        technique_name: get_mitre_name(mitre_id),
                        tactic: get_mitre_tactic(mitre_id),
                    };
                    if !mitre_mappings
                        .iter()
                        .any(|m: &MitreMapping| m.technique_id == mapping.technique_id)
                    {
                        mitre_mappings.push(mapping);
                    }
                }
            }
        }
    }

    // Generate reason
    let reason = if analyses.len() == 1 {
        scorer::generate_reason(&analyses[0])
    } else {
        let reasons: Vec<String> = analyses.iter().map(|a| scorer::generate_reason(a)).collect();
        if let Some(ref pf) = pipeline_flow {
            if !pf.taint_flows.is_empty() {
                let taint_desc = &pf.taint_flows[0].escalation_reason;
                format!("Pipeline: {}; {}", reasons.join(" | "), taint_desc)
            } else {
                reasons.join(" | ")
            }
        } else {
            reasons.join(" ; ")
        }
    };

    AnalysisResult {
        command: command.to_string(),
        score: final_score,
        level,
        quick_decision,
        reason,
        risk_factors: all_risk_factors,
        sub_commands: analyses,
        pipeline_flow,
        mitre_mappings,
        parse_confidence,
    }
}

/// Quick: just the risk score (0-100).
pub fn risk_score(command: &str) -> u8 {
    classify(command, None).score
}

/// Quick: just the risk level.
pub fn risk_level(command: &str) -> RiskLevel {
    classify(command, None).level
}

/// Batch: classify multiple commands.
pub fn classify_batch(
    commands: &[&str],
    context: Option<&ClassifyContext>,
) -> Vec<AnalysisResult> {
    commands.iter().map(|cmd| classify(cmd, context)).collect()
}

fn get_mitre_name(id: &str) -> String {
    match id {
        "T1059.004" => "Command and Scripting Interpreter: Unix Shell".to_string(),
        "T1070.004" => "Indicator Removal: File Deletion".to_string(),
        "T1105" => "Ingress Tool Transfer".to_string(),
        "T1041" => "Exfiltration Over C2 Channel".to_string(),
        "T1204.002" => "User Execution: Malicious File".to_string(),
        "T1132.001" => "Data Encoding: Standard Encoding".to_string(),
        "T1074.001" => "Data Staged: Local Data Staging".to_string(),
        "T1048" => "Exfiltration Over Alternative Protocol".to_string(),
        "T1027" => "Obfuscated Files or Information".to_string(),
        "T1027.010" => "Obfuscated Files: Command Obfuscation".to_string(),
        "T1548.001" => "Abuse Elevation: Setuid and Setgid".to_string(),
        "T1222.002" => "File and Directory Permissions Modification: Linux".to_string(),
        "T1021.004" => "Remote Services: SSH".to_string(),
        "T1098" => "Account Manipulation".to_string(),
        "T1053.003" => "Scheduled Task/Job: Cron".to_string(),
        "T1195" => "Supply Chain Compromise".to_string(),
        "T1610" => "Deploy Container".to_string(),
        "T1543" => "Create or Modify System Process".to_string(),
        "T1562.001" => "Impair Defenses: Disable or Modify Tools".to_string(),
        _ => format!("MITRE ATT&CK {}", id),
    }
}

fn get_mitre_tactic(id: &str) -> String {
    match id {
        "T1059.004" => "Execution".to_string(),
        "T1070.004" => "Defense Evasion".to_string(),
        "T1105" => "Command and Control".to_string(),
        "T1041" | "T1048" => "Exfiltration".to_string(),
        "T1204.002" => "Execution".to_string(),
        "T1132.001" | "T1027" | "T1027.010" => "Defense Evasion".to_string(),
        "T1074.001" => "Collection".to_string(),
        "T1548.001" | "T1222.002" => "Privilege Escalation".to_string(),
        "T1021.004" => "Lateral Movement".to_string(),
        "T1098" => "Persistence".to_string(),
        "T1053.003" => "Execution".to_string(),
        "T1195" => "Supply Chain Compromise".to_string(),
        "T1610" => "Execution".to_string(),
        "T1543" => "Persistence".to_string(),
        "T1562.001" => "Defense Evasion".to_string(),
        _ => "Unknown".to_string(),
    }
}
