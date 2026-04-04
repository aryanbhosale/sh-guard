use crate::types::RiskFactor;

#[derive(Debug, Clone)]
pub struct TaintRule {
    pub name: &'static str,
    pub source: TaintSourcePattern,
    pub sink: TaintSinkPattern,
    pub propagator: Option<TaintPropPattern>,
    pub escalation: u8,
    pub risk_factor: RiskFactor,
    pub mitre: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSourcePattern {
    SensitiveFile,
    EnvironmentVar,
    AnyRead,
    NetworkDownload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSinkPattern {
    NetworkSend,
    Execution,
    FileWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintPropPattern {
    Encoding,
    Any,
}

pub static TAINT_RULES: &[TaintRule] = &[
    TaintRule {
        name: "sensitive_file_to_network",
        source: TaintSourcePattern::SensitiveFile,
        sink: TaintSinkPattern::NetworkSend,
        propagator: None,
        escalation: 30,
        risk_factor: RiskFactor::NetworkExfiltration,
        mitre: "T1041",
        description: "Sensitive file content sent to network",
    },
    TaintRule {
        name: "any_to_execution",
        source: TaintSourcePattern::AnyRead,
        sink: TaintSinkPattern::Execution,
        propagator: None,
        escalation: 35,
        risk_factor: RiskFactor::PipeToExecution,
        mitre: "T1059.004",
        description: "Data piped to shell execution",
    },
    TaintRule {
        name: "network_download_to_execution",
        source: TaintSourcePattern::NetworkDownload,
        sink: TaintSinkPattern::Execution,
        propagator: None,
        escalation: 35,
        risk_factor: RiskFactor::UntrustedExecution,
        mitre: "T1204.002",
        description: "Remote content piped to execution (curl|bash pattern)",
    },
    TaintRule {
        name: "sensitive_file_encoded_to_network",
        source: TaintSourcePattern::SensitiveFile,
        sink: TaintSinkPattern::NetworkSend,
        propagator: Some(TaintPropPattern::Encoding),
        escalation: 40,
        risk_factor: RiskFactor::ObfuscatedExfiltration,
        mitre: "T1132.001",
        description: "Sensitive data encoded then exfiltrated",
    },
    TaintRule {
        name: "sensitive_file_to_file_write",
        source: TaintSourcePattern::SensitiveFile,
        sink: TaintSinkPattern::FileWrite,
        propagator: None,
        escalation: 20,
        risk_factor: RiskFactor::SecretsExposure,
        mitre: "T1074.001",
        description: "Sensitive data copied to new location",
    },
    TaintRule {
        name: "env_var_to_network",
        source: TaintSourcePattern::EnvironmentVar,
        sink: TaintSinkPattern::NetworkSend,
        propagator: None,
        escalation: 30,
        risk_factor: RiskFactor::NetworkExfiltration,
        mitre: "T1041",
        description: "Environment variables exfiltrated to network",
    },
    TaintRule {
        name: "network_download_to_file_write",
        source: TaintSourcePattern::NetworkDownload,
        sink: TaintSinkPattern::FileWrite,
        propagator: None,
        escalation: 15,
        risk_factor: RiskFactor::Write,
        mitre: "T1105",
        description: "Remote content written to file",
    },
    TaintRule {
        name: "any_read_to_network",
        source: TaintSourcePattern::AnyRead,
        sink: TaintSinkPattern::NetworkSend,
        propagator: None,
        escalation: 20,
        risk_factor: RiskFactor::NetworkExfiltration,
        mitre: "T1048",
        description: "Local data sent to network",
    },
    TaintRule {
        name: "env_var_to_execution",
        source: TaintSourcePattern::EnvironmentVar,
        sink: TaintSinkPattern::Execution,
        propagator: None,
        escalation: 30,
        risk_factor: RiskFactor::CommandExecution,
        mitre: "T1059.004",
        description: "Environment variable content executed",
    },
    TaintRule {
        name: "sensitive_file_encoded_to_file_write",
        source: TaintSourcePattern::SensitiveFile,
        sink: TaintSinkPattern::FileWrite,
        propagator: Some(TaintPropPattern::Encoding),
        escalation: 25,
        risk_factor: RiskFactor::ObfuscatedCommand,
        mitre: "T1027",
        description: "Sensitive data encoded and written to file",
    },
    TaintRule {
        name: "any_read_encoded_to_network",
        source: TaintSourcePattern::AnyRead,
        sink: TaintSinkPattern::NetworkSend,
        propagator: Some(TaintPropPattern::Encoding),
        escalation: 30,
        risk_factor: RiskFactor::ObfuscatedExfiltration,
        mitre: "T1132.001",
        description: "Data encoded then exfiltrated",
    },
    TaintRule {
        name: "env_var_encoded_to_network",
        source: TaintSourcePattern::EnvironmentVar,
        sink: TaintSinkPattern::NetworkSend,
        propagator: Some(TaintPropPattern::Encoding),
        escalation: 35,
        risk_factor: RiskFactor::ObfuscatedExfiltration,
        mitre: "T1132.001",
        description: "Environment variables encoded then exfiltrated",
    },
    TaintRule {
        name: "network_download_encoded_to_execution",
        source: TaintSourcePattern::NetworkDownload,
        sink: TaintSinkPattern::Execution,
        propagator: Some(TaintPropPattern::Encoding),
        escalation: 40,
        risk_factor: RiskFactor::UntrustedExecution,
        mitre: "T1027.010",
        description: "Remote content decoded then executed",
    },
    TaintRule {
        name: "any_read_to_file_write",
        source: TaintSourcePattern::AnyRead,
        sink: TaintSinkPattern::FileWrite,
        propagator: None,
        escalation: 10,
        risk_factor: RiskFactor::Write,
        mitre: "T1074.001",
        description: "Data read and written to new location",
    },
    TaintRule {
        name: "sensitive_file_to_execution",
        source: TaintSourcePattern::SensitiveFile,
        sink: TaintSinkPattern::Execution,
        propagator: None,
        escalation: 35,
        risk_factor: RiskFactor::CommandExecution,
        mitre: "T1059.004",
        description: "Sensitive file content executed as commands",
    },
];

/// Find the highest-escalation matching taint rule for a source-sink pair.
pub fn find_taint_escalation(
    source: &TaintSourcePattern,
    sink: &TaintSinkPattern,
    has_encoding_propagator: bool,
) -> Option<&'static TaintRule> {
    TAINT_RULES
        .iter()
        .filter(|r| {
            source_matches(&r.source, source)
                && r.sink == *sink
                && match &r.propagator {
                    None => true, // No-propagator rules always apply
                    Some(TaintPropPattern::Encoding) => has_encoding_propagator,
                    Some(TaintPropPattern::Any) => true,
                }
        })
        .max_by_key(|r| r.escalation)
}

fn source_matches(rule_source: &TaintSourcePattern, actual: &TaintSourcePattern) -> bool {
    if rule_source == actual {
        return true;
    }
    // AnyRead matches SensitiveFile and EnvironmentVar and NetworkDownload
    if *rule_source == TaintSourcePattern::AnyRead {
        return true;
    }
    false
}
