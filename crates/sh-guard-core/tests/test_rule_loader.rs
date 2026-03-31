use sh_guard_core::test_internals::rules;
use sh_guard_core::types::*;
use std::io::Write;

// ========================================================
// Helper: write a temporary TOML file
// ========================================================

fn write_temp_toml(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(content.as_bytes()).expect("write temp file");
    f.flush().expect("flush");
    f
}

// ========================================================
// RuleSet::builtin()
// ========================================================

#[test]
fn builtin_creates_empty_user_rules() {
    let rs = rules::RuleSet::builtin();
    assert!(rs.user_commands.is_empty());
    assert!(rs.user_paths.is_empty());
}

#[test]
fn builtin_does_not_interfere_with_builtin_lookup() {
    let _rs = rules::RuleSet::builtin();
    // Built-in lookup should still work
    assert!(rules::lookup_command("rm").is_some());
    assert!(rules::lookup_command("ls").is_some());
}

// ========================================================
// TOML loading: user commands
// ========================================================

#[test]
fn loads_custom_command_from_toml() {
    let toml = r#"
[[commands]]
name = "my-deploy"
intent = "execute"
base_weight = 60
reversibility = "hard_to_reverse"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(rs.user_commands.len(), 1);
    assert_eq!(rs.user_commands[0].name, "my-deploy");
    assert_eq!(rs.user_commands[0].intent, Intent::Execute);
    assert_eq!(rs.user_commands[0].base_weight, 60);
    assert_eq!(rs.user_commands[0].reversibility, Reversibility::HardToReverse);
}

#[test]
fn cannot_override_builtin_rm() {
    let toml = r#"
[[commands]]
name = "rm"
intent = "info"
base_weight = 0
reversibility = "reversible"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    // Should silently skip — rm is a built-in
    assert!(rs.user_commands.is_empty());
    // Built-in rm should still have its original intent
    let builtin = rules::lookup_command("rm").unwrap();
    assert_eq!(builtin.intent, Intent::Delete);
}

#[test]
fn cannot_override_builtin_curl() {
    let toml = r#"
[[commands]]
name = "curl"
intent = "info"
base_weight = 0
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert!(rs.user_commands.is_empty());
}

#[test]
fn skips_command_with_empty_name() {
    let toml = r#"
[[commands]]
name = ""
intent = "execute"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert!(rs.user_commands.is_empty());
}

#[test]
fn loads_multiple_custom_commands() {
    let toml = r#"
[[commands]]
name = "deploy-prod"
intent = "execute"
base_weight = 70

[[commands]]
name = "run-tests"
intent = "info"
base_weight = 5
reversibility = "reversible"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(rs.user_commands.len(), 2);
    assert_eq!(rs.user_commands[0].name, "deploy-prod");
    assert_eq!(rs.user_commands[1].name, "run-tests");
    assert_eq!(rs.user_commands[1].intent, Intent::Info);
    assert_eq!(rs.user_commands[1].reversibility, Reversibility::Reversible);
}

#[test]
fn lookup_user_command_finds_loaded_command() {
    let toml = r#"
[[commands]]
name = "my-tool"
intent = "write"
base_weight = 40
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    let found = rs.lookup_user_command("my-tool");
    assert!(found.is_some());
    assert_eq!(found.unwrap().intent, Intent::Write);
}

#[test]
fn lookup_user_command_strips_path() {
    let toml = r#"
[[commands]]
name = "my-tool"
intent = "write"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    let found = rs.lookup_user_command("/usr/local/bin/my-tool");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "my-tool");
}

#[test]
fn lookup_user_command_returns_none_for_unknown() {
    let rs = rules::RuleSet::builtin();
    assert!(rs.lookup_user_command("nonexistent").is_none());
}

#[test]
fn base_weight_defaults_to_intent_weight() {
    let toml = r#"
[[commands]]
name = "my-reader"
intent = "read"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(rs.user_commands[0].base_weight, Intent::Read.weight());
}

#[test]
fn base_weight_clamped_to_100() {
    let toml = r#"
[[commands]]
name = "extreme"
intent = "execute"
base_weight = 200
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(rs.user_commands[0].base_weight, 100);
}

#[test]
fn base_weight_clamped_to_0() {
    let toml = r#"
[[commands]]
name = "negative"
intent = "execute"
base_weight = -50
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(rs.user_commands[0].base_weight, 0);
}

#[test]
fn reversibility_defaults_to_hard_to_reverse() {
    let toml = r#"
[[commands]]
name = "something"
intent = "write"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(
        rs.user_commands[0].reversibility,
        Reversibility::HardToReverse
    );
}

#[test]
fn intent_defaults_to_execute() {
    let toml = r#"
[[commands]]
name = "mystery"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(rs.user_commands[0].intent, Intent::Execute);
}

// ========================================================
// TOML loading: user paths
// ========================================================

#[test]
fn loads_user_path_rule() {
    let toml = r#"
[[paths]]
pattern = "*.vault"
sensitivity = "secrets"
description = "Vault encrypted file"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(rs.user_paths.len(), 1);
    assert_eq!(rs.user_paths[0].pattern, "*.vault");
    assert_eq!(rs.user_paths[0].sensitivity, Sensitivity::Secrets);
    assert_eq!(rs.user_paths[0].description, "Vault encrypted file");
}

#[test]
fn skips_path_with_empty_pattern() {
    let toml = r#"
[[paths]]
pattern = ""
sensitivity = "secrets"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert!(rs.user_paths.is_empty());
}

#[test]
fn path_sensitivity_defaults_to_normal() {
    let toml = r#"
[[paths]]
pattern = "*.tmp"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert_eq!(rs.user_paths[0].sensitivity, Sensitivity::Normal);
}

// ========================================================
// Error handling
// ========================================================

#[test]
fn nonexistent_file_returns_builtin() {
    let rs = rules::RuleSet::with_user_rules(std::path::Path::new("/nonexistent/rules.toml"));
    assert!(rs.user_commands.is_empty());
    assert!(rs.user_paths.is_empty());
}

#[test]
fn malformed_toml_returns_builtin() {
    let toml = "this is not { valid toml !!!";
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    assert!(rs.user_commands.is_empty());
}

#[test]
fn mixed_valid_and_invalid_commands() {
    let toml = r#"
[[commands]]
name = "good-cmd"
intent = "read"

[[commands]]
name = ""

[[commands]]
name = "rm"
intent = "info"

[[commands]]
name = "another-good"
intent = "write"
"#;
    let f = write_temp_toml(toml);
    let rs = rules::RuleSet::with_user_rules(f.path());
    // Only "good-cmd" and "another-good" should be loaded
    assert_eq!(rs.user_commands.len(), 2);
    assert_eq!(rs.user_commands[0].name, "good-cmd");
    assert_eq!(rs.user_commands[1].name, "another-good");
}

#[test]
fn all_intent_variants_parse() {
    let intents = [
        ("read", Intent::Read),
        ("write", Intent::Write),
        ("delete", Intent::Delete),
        ("execute", Intent::Execute),
        ("network", Intent::Network),
        ("privilege", Intent::Privilege),
        ("search", Intent::Search),
        ("info", Intent::Info),
        ("package_install", Intent::PackageInstall),
        ("git_mutation", Intent::GitMutation),
        ("env_modify", Intent::EnvModify),
        ("process_control", Intent::ProcessControl),
    ];

    for (idx, (intent_str, expected)) in intents.iter().enumerate() {
        let toml = format!(
            r#"
[[commands]]
name = "intent-test-{}"
intent = "{}"
"#,
            idx, intent_str
        );
        let f = write_temp_toml(&toml);
        let rs = rules::RuleSet::with_user_rules(f.path());
        assert_eq!(
            rs.user_commands[0].intent, *expected,
            "Failed for intent: {}",
            intent_str
        );
    }
}

#[test]
fn all_reversibility_variants_parse() {
    let variants = [
        ("reversible", Reversibility::Reversible),
        ("hard_to_reverse", Reversibility::HardToReverse),
        ("irreversible", Reversibility::Irreversible),
    ];
    for (idx, (rev_str, expected)) in variants.iter().enumerate() {
        let toml = format!(
            r#"
[[commands]]
name = "rev-test-{}"
intent = "info"
reversibility = "{}"
"#,
            idx, rev_str
        );
        let f = write_temp_toml(&toml);
        let rs = rules::RuleSet::with_user_rules(f.path());
        assert_eq!(
            rs.user_commands[0].reversibility, *expected,
            "Failed for reversibility: {}",
            rev_str
        );
    }
}
