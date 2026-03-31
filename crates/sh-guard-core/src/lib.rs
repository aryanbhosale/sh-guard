pub mod types;
pub use types::*;

pub(crate) mod parser;

#[doc(hidden)]
pub mod test_internals {
    pub use crate::parser::*;
}

/// Classify a shell command and return a rich analysis.
pub fn classify(command: &str, context: Option<&ClassifyContext>) -> AnalysisResult {
    let _ = context;
    let score = 0u8;
    let level = RiskLevel::from_score(score);
    AnalysisResult {
        command: command.to_string(),
        score,
        level,
        quick_decision: QuickDecision::from_level(level),
        reason: String::new(),
        risk_factors: vec![],
        sub_commands: vec![],
        pipeline_flow: None,
        mitre_mappings: vec![],
        parse_confidence: ParseConfidence::Full,
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
pub fn classify_batch(commands: &[&str], context: Option<&ClassifyContext>) -> Vec<AnalysisResult> {
    commands.iter().map(|cmd| classify(cmd, context)).collect()
}
