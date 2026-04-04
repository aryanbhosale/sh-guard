use crate::parser::ChainOperator;
use crate::rules::network::{self, TaintSinkPattern, TaintSourcePattern};
use crate::types::*;

/// Analyze data flow across pipeline segments.
pub fn analyze_pipeline(
    analyses: &[CommandAnalysis],
    operators: &[ChainOperator],
) -> Option<PipelineFlow> {
    if analyses.len() <= 1 {
        return None;
    }

    let flow_type = determine_flow_type(operators);
    let mut taint_flows = vec![];

    // For pipe operators, check data flow from each segment to the next
    for i in 0..analyses.len().saturating_sub(1) {
        let source_analysis = &analyses[i];

        // Determine what the source produces
        let source_pattern = classify_source(source_analysis);

        for j in 0..analyses.len() - i - 1 {
            let sink = &analyses[i + 1 + j];

            // Only check direct pipe connections (adjacent segments with Pipe operator)
            if i + j < operators.len() {
                let is_pipe = matches!(operators.get(i + j), Some(ChainOperator::Pipe));
                if !is_pipe {
                    continue; // && and || don't create data flow
                }
            }

            let sink_pattern = classify_sink(sink);

            if let Some(sink_pat) = &sink_pattern {
                // Check for encoding propagators between source and sink
                let has_encoding = analyses[i + 1..i + 1 + j]
                    .iter()
                    .any(|mid| is_encoding_command(mid));

                if let Some(source_pat) = &source_pattern {
                    if let Some(rule) =
                        network::find_taint_escalation(source_pat, sink_pat, has_encoding)
                    {
                        let source_taint = match source_pat {
                            TaintSourcePattern::SensitiveFile => {
                                let path = source_analysis
                                    .targets
                                    .iter()
                                    .find_map(|t| t.path.clone())
                                    .unwrap_or_default();
                                TaintSource::SensitiveFile { path }
                            }
                            TaintSourcePattern::EnvironmentVar => TaintSource::EnvironmentVar,
                            TaintSourcePattern::NetworkDownload => TaintSource::CommandOutput,
                            TaintSourcePattern::AnyRead => TaintSource::Stdin,
                        };

                        let sink_taint = match sink_pat {
                            TaintSinkPattern::NetworkSend => TaintSink::NetworkSend,
                            TaintSinkPattern::Execution => TaintSink::Execution,
                            TaintSinkPattern::FileWrite => {
                                let path = sink
                                    .targets
                                    .iter()
                                    .find_map(|t| t.path.clone())
                                    .unwrap_or_default();
                                TaintSink::FileWrite { path }
                            }
                        };

                        let mut propagators = vec![];
                        if has_encoding {
                            propagators.push(TaintProp::Encoding {
                                method: "base64".into(),
                            });
                        } else if j > 0 {
                            propagators.push(TaintProp::Passthrough);
                        }

                        taint_flows.push(TaintFlow {
                            source: source_taint,
                            propagators,
                            sink: sink_taint,
                            escalation: rule.escalation,
                            escalation_reason: rule.description.to_string(),
                        });
                    }
                }
            }
        }
    }

    if taint_flows.is_empty() && analyses.len() > 1 {
        // Pipeline exists but no taint flow detected
        return Some(PipelineFlow {
            flow_type,
            taint_flows: vec![],
            composite_score: analyses.iter().map(|a| a.score).max().unwrap_or(0),
        });
    }

    if taint_flows.is_empty() {
        return None;
    }

    // Composite score: max segment score + highest escalation
    let max_segment_score = analyses.iter().map(|a| a.score as u16).max().unwrap_or(0);
    let max_escalation = taint_flows
        .iter()
        .map(|f| f.escalation as u16)
        .max()
        .unwrap_or(0);
    let composite = (max_segment_score + max_escalation).min(100) as u8;

    Some(PipelineFlow {
        flow_type,
        taint_flows,
        composite_score: composite,
    })
}

/// Classify what a command segment produces as a taint source.
fn classify_source(analysis: &CommandAnalysis) -> Option<TaintSourcePattern> {
    // Check if this reads sensitive files
    let reads_sensitive = analysis.targets.iter().any(|t| {
        matches!(
            t.sensitivity,
            Sensitivity::Secrets | Sensitivity::System | Sensitivity::Protected
        )
    });

    if reads_sensitive && analysis.intent.contains(&Intent::Read) {
        return Some(TaintSourcePattern::SensitiveFile);
    }

    // Check if this reads environment variables
    if analysis.intent.contains(&Intent::EnvModify)
        || analysis.command.contains("printenv")
        || analysis.command.contains("$")
    {
        return Some(TaintSourcePattern::EnvironmentVar);
    }

    // Check if this downloads from network
    if analysis.intent.contains(&Intent::Network) {
        let exec_base = analysis
            .executable
            .as_deref()
            .map(|e| e.rsplit('/').next().unwrap_or(e));
        match exec_base {
            Some("curl" | "wget" | "fetch") => {
                // If it has POST/upload flags, it's a sink not a source
                let is_sending = analysis
                    .risk_factors
                    .contains(&RiskFactor::NetworkExfiltration);
                if !is_sending {
                    return Some(TaintSourcePattern::NetworkDownload);
                }
            }
            _ => {}
        }
    }

    // Any command that reads files
    if analysis.intent.contains(&Intent::Read) {
        return Some(TaintSourcePattern::AnyRead);
    }

    // Search commands produce output
    if analysis.intent.contains(&Intent::Search) || analysis.intent.contains(&Intent::Info) {
        return Some(TaintSourcePattern::AnyRead);
    }

    None
}

/// Classify what a command segment consumes as a taint sink.
fn classify_sink(analysis: &CommandAnalysis) -> Option<TaintSinkPattern> {
    let exec_base = analysis
        .executable
        .as_deref()
        .map(|e| e.rsplit('/').next().unwrap_or(e));

    // Execution sinks: sh, bash, eval, python, etc.
    if analysis.intent.contains(&Intent::Execute) {
        return Some(TaintSinkPattern::Execution);
    }

    // Network sinks: curl with POST, wget with post, nc, etc.
    if analysis.intent.contains(&Intent::Network) {
        let is_sending = analysis
            .flags
            .iter()
            .any(|f| matches!(f.risk_factor, RiskFactor::NetworkExfiltration))
            || matches!(exec_base, Some("nc" | "ncat" | "socat" | "telnet"));

        if is_sending {
            return Some(TaintSinkPattern::NetworkSend);
        }
    }

    // File write sinks
    if analysis.intent.contains(&Intent::Write) {
        return Some(TaintSinkPattern::FileWrite);
    }

    None
}

/// Check if a command is an encoding/transformation step.
fn is_encoding_command(analysis: &CommandAnalysis) -> bool {
    let exec_base = analysis
        .executable
        .as_deref()
        .map(|e| e.rsplit('/').next().unwrap_or(e));

    matches!(
        exec_base,
        Some(
            "base64"
                | "xxd"
                | "od"
                | "hexdump"
                | "gzip"
                | "gunzip"
                | "bzip2"
                | "bunzip2"
                | "xz"
                | "openssl"
                | "gpg"
                | "uuencode"
        )
    )
}

fn determine_flow_type(operators: &[ChainOperator]) -> FlowType {
    if operators.is_empty() {
        return FlowType::Pipe;
    }

    let has_pipe = operators.iter().any(|o| matches!(o, ChainOperator::Pipe));
    let has_and = operators.iter().any(|o| matches!(o, ChainOperator::And));
    let has_or = operators.iter().any(|o| matches!(o, ChainOperator::Or));
    let has_seq = operators
        .iter()
        .any(|o| matches!(o, ChainOperator::Sequence));

    let count = [has_pipe, has_and, has_or, has_seq]
        .iter()
        .filter(|&&v| v)
        .count();

    if count > 1 {
        FlowType::Mixed
    } else if has_pipe {
        FlowType::Pipe
    } else if has_and {
        FlowType::And
    } else if has_or {
        FlowType::Or
    } else {
        FlowType::Sequence
    }
}
