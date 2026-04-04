use rules::network::*;
use sh_guard_core::test_internals::rules;
use std::collections::HashSet;

// ========================================================
// Helper
// ========================================================

fn find(
    source: &TaintSourcePattern,
    sink: &TaintSinkPattern,
    encoding: bool,
) -> Option<&'static str> {
    find_taint_escalation(source, sink, encoding).map(|r| r.name)
}

// ========================================================
// No duplicate rule names
// ========================================================

#[test]
fn no_duplicate_rule_names() {
    let mut seen = HashSet::new();
    for r in TAINT_RULES {
        assert!(
            seen.insert(r.name),
            "duplicate taint rule name: '{}'",
            r.name
        );
    }
}

// ========================================================
// Rule count
// ========================================================

#[test]
fn rule_count_is_15() {
    assert_eq!(TAINT_RULES.len(), 15);
}

// ========================================================
// All rules have non-empty fields
// ========================================================

#[test]
fn all_rules_have_names() {
    for r in TAINT_RULES {
        assert!(!r.name.is_empty());
    }
}

#[test]
fn all_rules_have_descriptions() {
    for r in TAINT_RULES {
        assert!(
            !r.description.is_empty(),
            "rule '{}' has empty description",
            r.name
        );
    }
}

#[test]
fn all_rules_have_mitre() {
    for r in TAINT_RULES {
        assert!(!r.mitre.is_empty(), "rule '{}' has empty MITRE ID", r.name);
    }
}

#[test]
fn all_rules_have_positive_escalation() {
    for r in TAINT_RULES {
        assert!(r.escalation > 0, "rule '{}' has zero escalation", r.name);
    }
}

// ========================================================
// Exact source+sink matches (no encoding)
// ========================================================

#[test]
fn sensitive_file_to_network_send() {
    let result = find(
        &TaintSourcePattern::SensitiveFile,
        &TaintSinkPattern::NetworkSend,
        false,
    );
    assert_eq!(result, Some("sensitive_file_to_network"));
}

#[test]
fn sensitive_file_to_execution() {
    // AnyRead rules also match SensitiveFile; highest escalation wins
    // sensitive_file_to_execution has escalation 35, any_to_execution has 35
    let r = find_taint_escalation(
        &TaintSourcePattern::SensitiveFile,
        &TaintSinkPattern::Execution,
        false,
    )
    .unwrap();
    assert!(r.escalation == 35);
}

#[test]
fn sensitive_file_to_file_write() {
    // sensitive_file_to_file_write (20) vs any_read_to_file_write (10) -- highest is 20
    let r = find_taint_escalation(
        &TaintSourcePattern::SensitiveFile,
        &TaintSinkPattern::FileWrite,
        false,
    )
    .unwrap();
    assert_eq!(r.escalation, 20);
    assert_eq!(r.name, "sensitive_file_to_file_write");
}

#[test]
fn env_var_to_network_send() {
    let result = find(
        &TaintSourcePattern::EnvironmentVar,
        &TaintSinkPattern::NetworkSend,
        false,
    );
    // env_var_to_network (30) vs any_read_to_network (20) -- highest is 30
    assert_eq!(result, Some("env_var_to_network"));
}

#[test]
fn env_var_to_execution() {
    let r = find_taint_escalation(
        &TaintSourcePattern::EnvironmentVar,
        &TaintSinkPattern::Execution,
        false,
    )
    .unwrap();
    // env_var_to_execution (30) vs any_to_execution (35) -- highest is 35
    assert_eq!(r.escalation, 35);
    assert_eq!(r.name, "any_to_execution");
}

#[test]
fn network_download_to_execution() {
    let r = find_taint_escalation(
        &TaintSourcePattern::NetworkDownload,
        &TaintSinkPattern::Execution,
        false,
    )
    .unwrap();
    // network_download_to_execution (35) vs any_to_execution (35)
    assert!(r.escalation == 35);
}

#[test]
fn network_download_to_file_write() {
    let r = find_taint_escalation(
        &TaintSourcePattern::NetworkDownload,
        &TaintSinkPattern::FileWrite,
        false,
    )
    .unwrap();
    // network_download_to_file_write (15) vs any_read_to_file_write (10)
    assert_eq!(r.escalation, 15);
    assert_eq!(r.name, "network_download_to_file_write");
}

#[test]
fn any_read_to_network_send() {
    let result = find(
        &TaintSourcePattern::AnyRead,
        &TaintSinkPattern::NetworkSend,
        false,
    );
    assert_eq!(result, Some("any_read_to_network"));
}

#[test]
fn any_read_to_execution() {
    let result = find(
        &TaintSourcePattern::AnyRead,
        &TaintSinkPattern::Execution,
        false,
    );
    assert_eq!(result, Some("any_to_execution"));
}

#[test]
fn any_read_to_file_write() {
    let result = find(
        &TaintSourcePattern::AnyRead,
        &TaintSinkPattern::FileWrite,
        false,
    );
    assert_eq!(result, Some("any_read_to_file_write"));
}

// ========================================================
// Encoding propagator tests
// ========================================================

#[test]
fn sensitive_file_to_network_with_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::SensitiveFile,
        &TaintSinkPattern::NetworkSend,
        true,
    )
    .unwrap();
    // With encoding: sensitive_file_encoded_to_network (40) beats sensitive_file_to_network (30) and any_read_encoded_to_network (30)
    assert_eq!(r.escalation, 40);
    assert_eq!(r.name, "sensitive_file_encoded_to_network");
}

#[test]
fn env_var_to_network_with_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::EnvironmentVar,
        &TaintSinkPattern::NetworkSend,
        true,
    )
    .unwrap();
    // env_var_encoded_to_network (35) vs env_var_to_network (30) vs any_read_encoded_to_network (30) vs any_read_to_network (20)
    assert_eq!(r.escalation, 35);
    assert_eq!(r.name, "env_var_encoded_to_network");
}

#[test]
fn network_download_to_execution_with_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::NetworkDownload,
        &TaintSinkPattern::Execution,
        true,
    )
    .unwrap();
    // network_download_encoded_to_execution (40) beats network_download_to_execution (35)
    assert_eq!(r.escalation, 40);
    assert_eq!(r.name, "network_download_encoded_to_execution");
}

#[test]
fn sensitive_file_to_file_write_with_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::SensitiveFile,
        &TaintSinkPattern::FileWrite,
        true,
    )
    .unwrap();
    // sensitive_file_encoded_to_file_write (25) beats sensitive_file_to_file_write (20)
    assert_eq!(r.escalation, 25);
    assert_eq!(r.name, "sensitive_file_encoded_to_file_write");
}

#[test]
fn any_read_to_network_with_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::AnyRead,
        &TaintSinkPattern::NetworkSend,
        true,
    )
    .unwrap();
    // any_read_encoded_to_network (30) vs any_read_to_network (20)
    assert_eq!(r.escalation, 30);
    assert_eq!(r.name, "any_read_encoded_to_network");
}

// ========================================================
// Encoding-only rules do NOT match without encoding
// ========================================================

#[test]
fn encoding_rule_does_not_match_without_encoding() {
    // Without encoding, sensitive_file_encoded_to_network should NOT be selected
    let r = find_taint_escalation(
        &TaintSourcePattern::SensitiveFile,
        &TaintSinkPattern::NetworkSend,
        false,
    )
    .unwrap();
    assert_eq!(r.name, "sensitive_file_to_network");
    assert_eq!(r.escalation, 30); // not 40
}

#[test]
fn network_encoded_execution_not_without_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::NetworkDownload,
        &TaintSinkPattern::Execution,
        false,
    )
    .unwrap();
    assert_ne!(r.name, "network_download_encoded_to_execution");
}

// ========================================================
// Non-encoding rules still match when encoding is present
// ========================================================

#[test]
fn non_encoding_rules_still_candidate_with_encoding() {
    // When encoding is present, both encoding and non-encoding rules are candidates.
    // The highest escalation wins. For any_read+file_write with encoding:
    // any_read_to_file_write (10, no prop) is still a candidate
    let r = find_taint_escalation(
        &TaintSourcePattern::AnyRead,
        &TaintSinkPattern::FileWrite,
        true,
    )
    .unwrap();
    // Only any_read_to_file_write matches (no encoding-specific rule for AnyRead+FileWrite)
    assert_eq!(r.name, "any_read_to_file_write");
}

// ========================================================
// Source-sink pairs with no match return None
// ========================================================

// There is no direct EnvironmentVar+FileWrite rule (only AnyRead covers it)
// Actually AnyRead rules match everything, so let's verify no truly impossible combo exists.
// All three sinks have AnyRead rules, so every source returns Some.
// The only way to get None would be if we had a source not covered by AnyRead.
// Since AnyRead covers all, every valid combo returns Some.
// Let's verify this explicitly.

#[test]
fn all_source_sink_combos_return_some() {
    let sources = [
        TaintSourcePattern::SensitiveFile,
        TaintSourcePattern::EnvironmentVar,
        TaintSourcePattern::AnyRead,
        TaintSourcePattern::NetworkDownload,
    ];
    let sinks = [
        TaintSinkPattern::NetworkSend,
        TaintSinkPattern::Execution,
        TaintSinkPattern::FileWrite,
    ];
    for source in &sources {
        for sink in &sinks {
            assert!(
                find_taint_escalation(source, sink, false).is_some(),
                "expected Some for {:?} -> {:?}",
                source,
                sink
            );
        }
    }
}

// ========================================================
// find_taint_escalation returns the highest-escalation match
// ========================================================

#[test]
fn highest_escalation_wins_sensitive_file_execution() {
    // SensitiveFile+Execution: sensitive_file_to_execution(35), any_to_execution(35)
    let r = find_taint_escalation(
        &TaintSourcePattern::SensitiveFile,
        &TaintSinkPattern::Execution,
        false,
    )
    .unwrap();
    assert_eq!(r.escalation, 35);
}

#[test]
fn highest_escalation_wins_env_var_network_with_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::EnvironmentVar,
        &TaintSinkPattern::NetworkSend,
        true,
    )
    .unwrap();
    // env_var_encoded_to_network=35, env_var_to_network=30, any_read_encoded_to_network=30, any_read_to_network=20
    assert_eq!(r.escalation, 35);
}

// ========================================================
// MITRE IDs are valid format
// ========================================================

#[test]
fn mitre_ids_have_valid_format() {
    for r in TAINT_RULES {
        assert!(
            r.mitre.starts_with('T'),
            "rule '{}' has MITRE ID '{}' not starting with 'T'",
            r.name,
            r.mitre
        );
    }
}

// ========================================================
// Source matching: AnyRead matches all sources
// ========================================================

#[test]
fn any_read_rules_match_sensitive_file() {
    // any_to_execution should match when source is SensitiveFile
    let r = find_taint_escalation(
        &TaintSourcePattern::SensitiveFile,
        &TaintSinkPattern::Execution,
        false,
    )
    .unwrap();
    // Should be 35 since both any_to_execution and sensitive_file_to_execution are 35
    assert_eq!(r.escalation, 35);
}

#[test]
fn any_read_rules_match_network_download() {
    // any_to_execution should match when source is NetworkDownload
    let r = find_taint_escalation(
        &TaintSourcePattern::NetworkDownload,
        &TaintSinkPattern::Execution,
        false,
    )
    .unwrap();
    assert!(r.escalation >= 35);
}

#[test]
fn any_read_rules_match_env_var_for_file_write() {
    // EnvironmentVar+FileWrite: only any_read_to_file_write matches (via AnyRead)
    let r = find_taint_escalation(
        &TaintSourcePattern::EnvironmentVar,
        &TaintSinkPattern::FileWrite,
        false,
    )
    .unwrap();
    assert_eq!(r.name, "any_read_to_file_write");
    assert_eq!(r.escalation, 10);
}

// ========================================================
// Specific rule field validation
// ========================================================

#[test]
fn curl_bash_pattern_rule_exists() {
    let r = TAINT_RULES
        .iter()
        .find(|r| r.name == "network_download_to_execution")
        .unwrap();
    assert_eq!(r.mitre, "T1204.002");
    assert_eq!(r.escalation, 35);
}

#[test]
fn obfuscated_exfiltration_rules_exist() {
    let obfuscated: Vec<_> = TAINT_RULES
        .iter()
        .filter(|r| {
            r.propagator == Some(TaintPropPattern::Encoding)
                && r.sink == TaintSinkPattern::NetworkSend
        })
        .collect();
    assert!(
        obfuscated.len() >= 3,
        "expected at least 3 encoding+network rules"
    );
}

#[test]
fn all_encoding_rules_have_encoding_propagator() {
    for r in TAINT_RULES {
        if r.name.contains("encoded") {
            assert_eq!(
                r.propagator,
                Some(TaintPropPattern::Encoding),
                "rule '{}' has 'encoded' in name but no Encoding propagator",
                r.name
            );
        }
    }
}

#[test]
fn non_encoded_rules_have_no_propagator() {
    for r in TAINT_RULES {
        if !r.name.contains("encoded") {
            assert_eq!(
                r.propagator, None,
                "rule '{}' has no 'encoded' in name but has propagator {:?}",
                r.name, r.propagator
            );
        }
    }
}

// ========================================================
// Network download + file write with encoding
// ========================================================

#[test]
fn network_download_to_file_write_with_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::NetworkDownload,
        &TaintSinkPattern::FileWrite,
        true,
    )
    .unwrap();
    // network_download_to_file_write (15) vs any_read_to_file_write (10) -- no encoding-specific rule
    assert_eq!(r.escalation, 15);
}

// ========================================================
// Env var to execution with encoding
// ========================================================

#[test]
fn env_var_to_execution_with_encoding() {
    let r = find_taint_escalation(
        &TaintSourcePattern::EnvironmentVar,
        &TaintSinkPattern::Execution,
        true,
    )
    .unwrap();
    // env_var_to_execution (30) vs any_to_execution (35) -- no encoding specific env+exec rule
    assert_eq!(r.escalation, 35);
    assert_eq!(r.name, "any_to_execution");
}
