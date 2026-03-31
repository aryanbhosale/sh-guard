use sh_guard_core::*;

// ========================================================
// 1. RiskLevel::from_score — exhaustive over 0..=100
// ========================================================

#[test]
fn risk_level_from_score_safe_range() {
    for score in 0..=20u8 {
        assert_eq!(
            RiskLevel::from_score(score),
            RiskLevel::Safe,
            "score {score} should be Safe"
        );
    }
}

#[test]
fn risk_level_from_score_caution_range() {
    for score in 21..=50u8 {
        assert_eq!(
            RiskLevel::from_score(score),
            RiskLevel::Caution,
            "score {score} should be Caution"
        );
    }
}

#[test]
fn risk_level_from_score_danger_range() {
    for score in 51..=80u8 {
        assert_eq!(
            RiskLevel::from_score(score),
            RiskLevel::Danger,
            "score {score} should be Danger"
        );
    }
}

#[test]
fn risk_level_from_score_critical_range() {
    for score in 81..=100u8 {
        assert_eq!(
            RiskLevel::from_score(score),
            RiskLevel::Critical,
            "score {score} should be Critical"
        );
    }
}

// Scores above 100 should still map to Critical
#[test]
fn risk_level_from_score_above_100() {
    for score in 101..=255u8 {
        assert_eq!(
            RiskLevel::from_score(score),
            RiskLevel::Critical,
            "score {score} should be Critical"
        );
    }
}

// ========================================================
// 2. RiskLevel ordering
// ========================================================

#[test]
fn risk_level_ordering() {
    assert!(RiskLevel::Safe < RiskLevel::Caution);
    assert!(RiskLevel::Caution < RiskLevel::Danger);
    assert!(RiskLevel::Danger < RiskLevel::Critical);
}

// ========================================================
// 3. QuickDecision::from_level
// ========================================================

#[test]
fn quick_decision_from_level_safe() {
    assert_eq!(QuickDecision::from_level(RiskLevel::Safe), QuickDecision::Safe);
}

#[test]
fn quick_decision_from_level_caution() {
    assert_eq!(
        QuickDecision::from_level(RiskLevel::Caution),
        QuickDecision::Risky
    );
}

#[test]
fn quick_decision_from_level_danger() {
    assert_eq!(
        QuickDecision::from_level(RiskLevel::Danger),
        QuickDecision::Risky
    );
}

#[test]
fn quick_decision_from_level_critical() {
    assert_eq!(
        QuickDecision::from_level(RiskLevel::Critical),
        QuickDecision::Blocked
    );
}

// ========================================================
// 4. Intent::weight() — exact values for all 12 variants
// ========================================================

#[test]
fn intent_weight_info() {
    assert_eq!(Intent::Info.weight(), 0);
}

#[test]
fn intent_weight_search() {
    assert_eq!(Intent::Search.weight(), 5);
}

#[test]
fn intent_weight_read() {
    assert_eq!(Intent::Read.weight(), 10);
}

#[test]
fn intent_weight_write() {
    assert_eq!(Intent::Write.weight(), 30);
}

#[test]
fn intent_weight_package_install() {
    assert_eq!(Intent::PackageInstall.weight(), 35);
}

#[test]
fn intent_weight_git_mutation() {
    assert_eq!(Intent::GitMutation.weight(), 35);
}

#[test]
fn intent_weight_env_modify() {
    assert_eq!(Intent::EnvModify.weight(), 40);
}

#[test]
fn intent_weight_network() {
    assert_eq!(Intent::Network.weight(), 40);
}

#[test]
fn intent_weight_process_control() {
    assert_eq!(Intent::ProcessControl.weight(), 40);
}

#[test]
fn intent_weight_delete() {
    assert_eq!(Intent::Delete.weight(), 45);
}

#[test]
fn intent_weight_execute() {
    assert_eq!(Intent::Execute.weight(), 50);
}

#[test]
fn intent_weight_privilege() {
    assert_eq!(Intent::Privilege.weight(), 55);
}

// ========================================================
// 5. TargetScope::modifier() — exact values for all 7 variants
// ========================================================

#[test]
fn target_scope_modifiers() {
    assert_eq!(TargetScope::None.modifier(), 0);
    assert_eq!(TargetScope::SingleFile.modifier(), 0);
    assert_eq!(TargetScope::Directory.modifier(), 5);
    assert_eq!(TargetScope::DirectoryRecursive.modifier(), 15);
    assert_eq!(TargetScope::System.modifier(), 25);
    assert_eq!(TargetScope::Home.modifier(), 30);
    assert_eq!(TargetScope::Root.modifier(), 40);
}

#[test]
fn target_scope_ordering() {
    assert!(TargetScope::None < TargetScope::SingleFile);
    assert!(TargetScope::SingleFile < TargetScope::Directory);
    assert!(TargetScope::Directory < TargetScope::DirectoryRecursive);
    assert!(TargetScope::DirectoryRecursive < TargetScope::System);
    assert!(TargetScope::System < TargetScope::Home);
    assert!(TargetScope::Home < TargetScope::Root);
}

// ========================================================
// 6. Sensitivity::modifier() — exact values for all 5 variants
// ========================================================

#[test]
fn sensitivity_modifiers() {
    assert_eq!(Sensitivity::Normal.modifier(), 0);
    assert_eq!(Sensitivity::Config.modifier(), 10);
    assert_eq!(Sensitivity::System.modifier(), 20);
    assert_eq!(Sensitivity::Secrets.modifier(), 25);
    assert_eq!(Sensitivity::Protected.modifier(), 25);
}

// ========================================================
// 7. Reversibility::modifier() — exact values for all 3 variants
// ========================================================

#[test]
fn reversibility_modifiers() {
    assert_eq!(Reversibility::Reversible.modifier(), -10);
    assert_eq!(Reversibility::HardToReverse.modifier(), 5);
    assert_eq!(Reversibility::Irreversible.modifier(), 15);
}

// ========================================================
// 8. Serde round-trip tests
// ========================================================

fn serde_roundtrip<T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq>(
    val: &T,
) {
    let json = serde_json::to_string(val).expect("serialize");
    let back: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(val, &back, "round-trip failed for {:?}", val);
}

// --- RiskLevel (4 variants) ---
#[test]
fn serde_risk_level() {
    for v in [
        RiskLevel::Safe,
        RiskLevel::Caution,
        RiskLevel::Danger,
        RiskLevel::Critical,
    ] {
        serde_roundtrip(&v);
    }
}

// --- QuickDecision (3 variants) ---
#[test]
fn serde_quick_decision() {
    for v in [
        QuickDecision::Safe,
        QuickDecision::Risky,
        QuickDecision::Blocked,
    ] {
        serde_roundtrip(&v);
    }
}

// --- Intent (12 variants) ---
#[test]
fn serde_intent() {
    for v in [
        Intent::Read,
        Intent::Write,
        Intent::Delete,
        Intent::Execute,
        Intent::Network,
        Intent::ProcessControl,
        Intent::Privilege,
        Intent::PackageInstall,
        Intent::GitMutation,
        Intent::EnvModify,
        Intent::Search,
        Intent::Info,
    ] {
        serde_roundtrip(&v);
    }
}

// --- TargetScope (7 variants) ---
#[test]
fn serde_target_scope() {
    for v in [
        TargetScope::None,
        TargetScope::SingleFile,
        TargetScope::Directory,
        TargetScope::DirectoryRecursive,
        TargetScope::System,
        TargetScope::Home,
        TargetScope::Root,
    ] {
        serde_roundtrip(&v);
    }
}

// --- Sensitivity (5 variants) ---
#[test]
fn serde_sensitivity() {
    for v in [
        Sensitivity::Normal,
        Sensitivity::Config,
        Sensitivity::System,
        Sensitivity::Secrets,
        Sensitivity::Protected,
    ] {
        serde_roundtrip(&v);
    }
}

// --- Reversibility (3 variants) ---
#[test]
fn serde_reversibility() {
    for v in [
        Reversibility::Reversible,
        Reversibility::HardToReverse,
        Reversibility::Irreversible,
    ] {
        serde_roundtrip(&v);
    }
}

// --- BinaryCapability (10 variants) ---
#[test]
fn serde_binary_capability() {
    for v in [
        BinaryCapability::Shell,
        BinaryCapability::Command,
        BinaryCapability::ReverseShell,
        BinaryCapability::BindShell,
        BinaryCapability::FileRead,
        BinaryCapability::FileWrite,
        BinaryCapability::Upload,
        BinaryCapability::Download,
        BinaryCapability::LibraryLoad,
        BinaryCapability::PrivilegeEscalation,
    ] {
        serde_roundtrip(&v);
    }
}

// --- RiskFactor (20 variants) ---
#[test]
fn serde_risk_factor() {
    for v in [
        RiskFactor::RecursiveDelete,
        RiskFactor::ForceFlag,
        RiskFactor::BroadScope,
        RiskFactor::SecretsExposure,
        RiskFactor::NetworkExfiltration,
        RiskFactor::PipeToExecution,
        RiskFactor::CommandSubstitution,
        RiskFactor::ProcessSubstitution,
        RiskFactor::UntrustedExecution,
        RiskFactor::PrivilegeEscalation,
        RiskFactor::PathInjection,
        RiskFactor::GitHistoryDestruction,
        RiskFactor::EscapesProjectBoundary,
        RiskFactor::ShellInjection,
        RiskFactor::ZshModuleLoading,
        RiskFactor::ZshGlobExecution,
        RiskFactor::ObfuscatedCommand,
        RiskFactor::ObfuscatedExfiltration,
        RiskFactor::CommandExecution,
        RiskFactor::Write,
    ] {
        serde_roundtrip(&v);
    }
}

// --- FlowType (5 variants) ---
#[test]
fn serde_flow_type() {
    for v in [
        FlowType::Pipe,
        FlowType::And,
        FlowType::Or,
        FlowType::Sequence,
        FlowType::Mixed,
    ] {
        serde_roundtrip(&v);
    }
}

// --- ParseConfidence (3 variants) ---
#[test]
fn serde_parse_confidence() {
    for v in [
        ParseConfidence::Full,
        ParseConfidence::Partial,
        ParseConfidence::Fallback,
    ] {
        serde_roundtrip(&v);
    }
}

// --- Shell (2 variants) ---
#[test]
fn serde_shell() {
    for v in [Shell::Bash, Shell::Zsh] {
        serde_roundtrip(&v);
    }
}

// --- TaintSource (4 tagged variants) ---
#[test]
fn serde_taint_source() {
    let variants: Vec<TaintSource> = vec![
        TaintSource::SensitiveFile {
            path: "/etc/passwd".to_string(),
        },
        TaintSource::EnvironmentVar,
        TaintSource::CommandOutput,
        TaintSource::Stdin,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let back: TaintSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, &back);
    }
}

// --- TaintProp (4 variants) ---
#[test]
fn serde_taint_prop() {
    let variants: Vec<TaintProp> = vec![
        TaintProp::Passthrough,
        TaintProp::Encoding {
            method: "base64".to_string(),
        },
        TaintProp::Filtering,
        TaintProp::Aggregation,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let back: TaintProp = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, &back);
    }
}

// --- TaintSink (4 tagged variants) ---
#[test]
fn serde_taint_sink() {
    let variants: Vec<TaintSink> = vec![
        TaintSink::NetworkSend,
        TaintSink::FileWrite {
            path: "/tmp/out".to_string(),
        },
        TaintSink::Execution,
        TaintSink::Display,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let back: TaintSink = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, &back);
    }
}

// ========================================================
// 9. ClassifyContext defaults
// ========================================================

#[test]
fn classify_context_default_shell_is_bash() {
    let ctx: ClassifyContext = serde_json::from_str("{}").expect("deserialize empty");
    assert_eq!(ctx.shell, Shell::Bash);
}

#[test]
fn classify_context_default_protected_paths_is_empty() {
    let ctx: ClassifyContext = serde_json::from_str("{}").expect("deserialize empty");
    assert!(ctx.protected_paths.is_empty());
}

#[test]
fn classify_context_full_roundtrip() {
    let ctx = ClassifyContext {
        cwd: Some("/home/user".to_string()),
        project_root: Some("/home/user/project".to_string()),
        home_dir: Some("/home/user".to_string()),
        protected_paths: vec!["/etc".to_string(), "/usr".to_string()],
        shell: Shell::Zsh,
    };
    let json = serde_json::to_string(&ctx).expect("serialize");
    let back: ClassifyContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.cwd, ctx.cwd);
    assert_eq!(back.project_root, ctx.project_root);
    assert_eq!(back.home_dir, ctx.home_dir);
    assert_eq!(back.protected_paths, ctx.protected_paths);
    assert_eq!(back.shell, ctx.shell);
}

// ========================================================
// 10. Serde exact JSON values (snake_case rename)
// ========================================================

#[test]
fn serde_risk_level_exact_json_values() {
    assert_eq!(serde_json::to_string(&RiskLevel::Safe).unwrap(), "\"safe\"");
    assert_eq!(
        serde_json::to_string(&RiskLevel::Caution).unwrap(),
        "\"caution\""
    );
    assert_eq!(
        serde_json::to_string(&RiskLevel::Danger).unwrap(),
        "\"danger\""
    );
    assert_eq!(
        serde_json::to_string(&RiskLevel::Critical).unwrap(),
        "\"critical\""
    );
}

#[test]
fn serde_intent_exact_json_values() {
    assert_eq!(serde_json::to_string(&Intent::Read).unwrap(), "\"read\"");
    assert_eq!(
        serde_json::to_string(&Intent::ProcessControl).unwrap(),
        "\"process_control\""
    );
    assert_eq!(
        serde_json::to_string(&Intent::PackageInstall).unwrap(),
        "\"package_install\""
    );
    assert_eq!(
        serde_json::to_string(&Intent::GitMutation).unwrap(),
        "\"git_mutation\""
    );
    assert_eq!(
        serde_json::to_string(&Intent::EnvModify).unwrap(),
        "\"env_modify\""
    );
}

#[test]
fn serde_target_scope_exact_json_values() {
    assert_eq!(
        serde_json::to_string(&TargetScope::DirectoryRecursive).unwrap(),
        "\"directory_recursive\""
    );
    assert_eq!(
        serde_json::to_string(&TargetScope::SingleFile).unwrap(),
        "\"single_file\""
    );
}

#[test]
fn serde_risk_factor_exact_json_values() {
    assert_eq!(
        serde_json::to_string(&RiskFactor::RecursiveDelete).unwrap(),
        "\"recursive_delete\""
    );
    assert_eq!(
        serde_json::to_string(&RiskFactor::PipeToExecution).unwrap(),
        "\"pipe_to_execution\""
    );
    assert_eq!(
        serde_json::to_string(&RiskFactor::ZshGlobExecution).unwrap(),
        "\"zsh_glob_execution\""
    );
}

// ========================================================
// 11. AnalysisResult struct round-trip
// ========================================================

#[test]
fn analysis_result_roundtrip() {
    let result = AnalysisResult {
        command: "rm -rf /".to_string(),
        score: 100,
        level: RiskLevel::Critical,
        quick_decision: QuickDecision::Blocked,
        reason: "Recursive delete of root".to_string(),
        risk_factors: vec![RiskFactor::RecursiveDelete, RiskFactor::ForceFlag],
        sub_commands: vec![CommandAnalysis {
            command: "rm -rf /".to_string(),
            executable: Some("rm".to_string()),
            intent: vec![Intent::Delete],
            targets: vec![Target {
                path: Some("/".to_string()),
                scope: TargetScope::Root,
                sensitivity: Sensitivity::System,
            }],
            flags: vec![FlagAnalysis {
                flag: "-r".to_string(),
                modifier: 20,
                risk_factor: RiskFactor::RecursiveDelete,
                description: "recursive".to_string(),
            }],
            score: 100,
            risk_factors: vec![RiskFactor::RecursiveDelete],
            reversibility: Reversibility::Irreversible,
            capabilities: vec![],
        }],
        pipeline_flow: Some(PipelineFlow {
            flow_type: FlowType::Pipe,
            taint_flows: vec![TaintFlow {
                source: TaintSource::SensitiveFile {
                    path: "/etc/shadow".to_string(),
                },
                propagators: vec![TaintProp::Passthrough],
                sink: TaintSink::NetworkSend,
                escalation: 30,
                escalation_reason: "sensitive data to network".to_string(),
            }],
            composite_score: 95,
        }),
        mitre_mappings: vec![MitreMapping {
            technique_id: "T1485".to_string(),
            technique_name: "Data Destruction".to_string(),
            tactic: "Impact".to_string(),
        }],
        parse_confidence: ParseConfidence::Full,
    };

    let json = serde_json::to_string(&result).expect("serialize");
    let back: AnalysisResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.command, result.command);
    assert_eq!(back.score, result.score);
    assert_eq!(back.level, result.level);
    assert_eq!(back.quick_decision, result.quick_decision);
    assert_eq!(back.reason, result.reason);
    assert_eq!(back.risk_factors.len(), 2);
    assert_eq!(back.sub_commands.len(), 1);
    assert!(back.pipeline_flow.is_some());
    assert_eq!(back.mitre_mappings.len(), 1);
    assert_eq!(back.parse_confidence, ParseConfidence::Full);
}

// ========================================================
// 12. classify stub returns sane defaults
// ========================================================

#[test]
fn classify_returns_safe_for_echo() {
    let result = classify("echo hello", None);
    assert_eq!(result.command, "echo hello");
    assert!(result.score <= 10, "echo hello scored {}", result.score);
    assert_eq!(result.level, RiskLevel::Safe);
    assert_eq!(result.quick_decision, QuickDecision::Safe);
    assert!(!result.sub_commands.is_empty()); // Now produces sub-commands
    assert!(result.pipeline_flow.is_none());
    assert_eq!(result.parse_confidence, ParseConfidence::Full);
}

#[test]
fn risk_score_safe_for_ls() {
    assert!(risk_score("ls") <= 10);
}

#[test]
fn risk_level_safe_for_ls() {
    assert_eq!(risk_level("ls"), RiskLevel::Safe);
}

#[test]
fn classify_batch_safe_commands() {
    let results = classify_batch(&["ls", "pwd", "echo hi"], None);
    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(r.score <= 20, "safe command scored {}", r.score);
        assert_eq!(r.level, RiskLevel::Safe);
    }
}

#[test]
fn classify_with_context() {
    let ctx = ClassifyContext {
        cwd: Some("/tmp".to_string()),
        project_root: None,
        home_dir: None,
        protected_paths: vec![],
        shell: Shell::Bash,
    };
    let result = classify("ls", Some(&ctx));
    assert_eq!(result.command, "ls");
    assert!(result.score <= 10);
}
