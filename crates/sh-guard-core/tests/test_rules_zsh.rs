use sh_guard_core::test_internals::rules;
use std::collections::HashSet;

// ========================================================
// Helper
// ========================================================

fn detect(cmd: &str) -> Vec<&'static str> {
    rules::zsh::detect_zsh_patterns(cmd)
        .into_iter()
        .map(|(name, _, _, _)| name)
        .collect()
}

fn detects_rule(name: &str, cmd: &str) -> bool {
    detect(cmd).contains(&name)
}

// ========================================================
// No duplicate rule names
// ========================================================

#[test]
fn no_duplicate_rule_names() {
    let mut seen = HashSet::new();
    for r in rules::zsh::ZSH_RULES {
        assert!(seen.insert(r.name), "duplicate zsh rule name: '{}'", r.name);
    }
}

// ========================================================
// Rule count
// ========================================================

#[test]
fn rule_count_is_15() {
    assert_eq!(rules::zsh::ZSH_RULES.len(), 15);
}

// ========================================================
// zmodload
// ========================================================

#[test]
fn zmodload_positive() {
    assert!(detects_rule("zmodload", "zmodload zsh/system"));
}

#[test]
fn zmodload_negative() {
    assert!(!detects_rule("zmodload", "echo hello"));
}

// ========================================================
// zsh_system_module
// ========================================================

#[test]
fn zsh_system_module_positive() {
    assert!(detects_rule("zsh_system_module", "zmodload zsh/system"));
}

#[test]
fn zsh_system_module_negative() {
    assert!(!detects_rule("zsh_system_module", "zmodload zsh/zpty"));
}

// ========================================================
// zsh_zpty_module
// ========================================================

#[test]
fn zsh_zpty_module_positive_module() {
    assert!(detects_rule("zsh_zpty_module", "zmodload zsh/zpty"));
}

#[test]
fn zsh_zpty_module_positive_command() {
    assert!(detects_rule("zsh_zpty_module", "zpty my_session cat"));
}

#[test]
fn zsh_zpty_module_negative() {
    assert!(!detects_rule("zsh_zpty_module", "echo hello world"));
}

// ========================================================
// zsh_net_tcp
// ========================================================

#[test]
fn zsh_net_tcp_positive_module() {
    assert!(detects_rule("zsh_net_tcp", "zmodload zsh/net/tcp"));
}

#[test]
fn zsh_net_tcp_positive_command() {
    assert!(detects_rule("zsh_net_tcp", "ztcp example.com 80"));
}

#[test]
fn zsh_net_tcp_negative() {
    assert!(!detects_rule("zsh_net_tcp", "curl http://example.com"));
}

// ========================================================
// zsh_net_socket
// ========================================================

#[test]
fn zsh_net_socket_positive_module() {
    assert!(detects_rule("zsh_net_socket", "zmodload zsh/net/socket"));
}

#[test]
fn zsh_net_socket_positive_command() {
    assert!(detects_rule("zsh_net_socket", "zsocket /tmp/mysock"));
}

#[test]
fn zsh_net_socket_negative() {
    assert!(!detects_rule("zsh_net_socket", "socket_file=/tmp/mysock"));
}

// ========================================================
// zsh_mapfile
// ========================================================

#[test]
fn zsh_mapfile_positive_module() {
    assert!(detects_rule("zsh_mapfile", "zmodload zsh/mapfile"));
}

#[test]
fn zsh_mapfile_positive_command() {
    assert!(detects_rule("zsh_mapfile", "echo $mapfile[/etc/passwd]"));
}

#[test]
fn zsh_mapfile_negative() {
    assert!(!detects_rule("zsh_mapfile", "echo hello"));
}

// ========================================================
// zsh_files_module
// ========================================================

#[test]
fn zsh_files_module_positive_module() {
    assert!(detects_rule("zsh_files_module", "zmodload zsh/files"));
}

#[test]
fn zsh_files_module_positive_zf_rm() {
    assert!(detects_rule("zsh_files_module", "zf_rm /tmp/file"));
}

#[test]
fn zsh_files_module_positive_zf_chmod() {
    assert!(detects_rule("zsh_files_module", "zf_chmod 755 script.sh"));
}

#[test]
fn zsh_files_module_negative() {
    assert!(!detects_rule("zsh_files_module", "rm /tmp/file"));
}

// ========================================================
// emulate_eval
// ========================================================

#[test]
fn emulate_eval_positive() {
    assert!(detects_rule("emulate_eval", "emulate -L zsh -c 'echo hi'"));
}

#[test]
fn emulate_eval_negative_no_flag() {
    assert!(!detects_rule("emulate_eval", "emulate zsh"));
}

#[test]
fn emulate_eval_negative_no_emulate() {
    assert!(!detects_rule("emulate_eval", "echo -c something"));
}

// ========================================================
// sysopen
// ========================================================

#[test]
fn sysopen_positive() {
    assert!(detects_rule("sysopen", "sysopen -r -u 3 /etc/passwd"));
}

#[test]
fn sysopen_negative() {
    assert!(!detects_rule("sysopen", "open /etc/passwd"));
}

// ========================================================
// sysread_syswrite
// ========================================================

#[test]
fn sysread_positive() {
    assert!(detects_rule("sysread_syswrite", "sysread buf"));
}

#[test]
fn syswrite_positive() {
    assert!(detects_rule("sysread_syswrite", "syswrite data"));
}

#[test]
fn sysseek_positive() {
    assert!(detects_rule("sysread_syswrite", "sysseek 0"));
}

#[test]
fn sysread_syswrite_negative() {
    assert!(!detects_rule("sysread_syswrite", "read buf"));
}

// ========================================================
// glob_qualifier_exec
// ========================================================

#[test]
fn glob_qualifier_exec_positive_e() {
    assert!(detects_rule(
        "glob_qualifier_exec",
        "print *(e:'[[ -d $REPLY ]]':)"
    ));
}

#[test]
fn glob_qualifier_exec_positive_plus() {
    assert!(detects_rule("glob_qualifier_exec", "print *(+myfunction)"));
}

#[test]
fn glob_qualifier_exec_negative() {
    assert!(!detects_rule("glob_qualifier_exec", "ls *.txt"));
}

// ========================================================
// equals_expansion
// ========================================================

#[test]
fn equals_expansion_positive() {
    assert!(detects_rule("equals_expansion", "cat =ls"));
}

#[test]
fn equals_expansion_positive_in_middle() {
    assert!(detects_rule("equals_expansion", "echo =python"));
}

#[test]
fn equals_expansion_negative_no_alpha() {
    assert!(!detects_rule("equals_expansion", "test x = y"));
}

#[test]
fn equals_expansion_negative_just_equals() {
    assert!(!detects_rule("equals_expansion", "x=5"));
}

// ========================================================
// always_block
// ========================================================

#[test]
fn always_block_positive() {
    assert!(detects_rule("always_block", "{ cmd } always { cleanup }"));
}

#[test]
fn always_block_negative() {
    assert!(!detects_rule("always_block", "echo hello world"));
}

// ========================================================
// precommand_noglob
// ========================================================

#[test]
fn precommand_noglob_positive_start() {
    assert!(detects_rule("precommand_noglob", "noglob echo *"));
}

#[test]
fn precommand_noglob_positive_middle() {
    assert!(detects_rule("precommand_noglob", "sudo noglob echo *"));
}

#[test]
fn precommand_noglob_negative() {
    assert!(!detects_rule("precommand_noglob", "echo noglob_var"));
}

// ========================================================
// zsh_autoload
// ========================================================

#[test]
fn zsh_autoload_positive() {
    assert!(detects_rule("zsh_autoload", "autoload -U compinit"));
}

#[test]
fn zsh_autoload_negative_no_flag() {
    assert!(!detects_rule("zsh_autoload", "autoload compinit"));
}

#[test]
fn zsh_autoload_negative_no_autoload() {
    assert!(!detects_rule("zsh_autoload", "echo -U something"));
}

// ========================================================
// All rules have non-zero scores
// ========================================================

#[test]
fn all_rules_have_positive_scores() {
    for r in rules::zsh::ZSH_RULES {
        assert!(r.score > 0, "rule '{}' has zero score", r.name);
    }
}

// ========================================================
// All rules have non-empty descriptions
// ========================================================

#[test]
fn all_rules_have_descriptions() {
    for r in rules::zsh::ZSH_RULES {
        assert!(
            !r.description.is_empty(),
            "rule '{}' has empty description",
            r.name
        );
    }
}

// ========================================================
// detect_zsh_patterns returns correct tuples
// ========================================================

#[test]
fn detect_zsh_patterns_returns_full_tuple() {
    let results = rules::zsh::detect_zsh_patterns("zmodload zsh/system");
    assert!(results.len() >= 2); // matches both zmodload and zsh_system_module
    for (name, score, _rf, desc) in &results {
        assert!(!name.is_empty());
        assert!(*score > 0);
        assert!(!desc.is_empty());
    }
}

// ========================================================
// Empty command matches nothing (except maybe always_block if contains "always")
// ========================================================

#[test]
fn empty_command_matches_nothing() {
    let results = detect("");
    assert!(results.is_empty());
}

// ========================================================
// Benign commands match no zsh rules
// ========================================================

#[test]
fn benign_command_no_match() {
    let results = detect("ls -la /tmp");
    assert!(results.is_empty());
}
