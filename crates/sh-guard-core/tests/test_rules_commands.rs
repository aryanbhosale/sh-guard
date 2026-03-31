use sh_guard_core::test_internals::rules;
use sh_guard_core::types::*;
use std::collections::HashSet;

// ========================================================
// Helper
// ========================================================

fn lookup(name: &str) -> &'static rules::CommandRule {
    rules::lookup_command(name).unwrap_or_else(|| panic!("expected rule for '{}'", name))
}

// ========================================================
// lookup_command basic behavior
// ========================================================

#[test]
fn lookup_strips_path_prefix() {
    let rule = rules::lookup_command("/usr/bin/ls").expect("should strip path");
    assert_eq!(rule.name, "ls");
    assert_eq!(rule.intent, Intent::Info);
}

#[test]
fn lookup_strips_deep_path() {
    let rule = rules::lookup_command("/usr/local/bin/grep").expect("should strip deep path");
    assert_eq!(rule.name, "grep");
}

#[test]
fn lookup_nonexistent_returns_none() {
    assert!(rules::lookup_command("nonexistent_cmd_xyz").is_none());
}

#[test]
fn lookup_empty_string_returns_none() {
    assert!(rules::lookup_command("").is_none());
}

// ========================================================
// No duplicate command names in the table
// ========================================================

#[test]
fn no_duplicate_command_names() {
    let mut seen = HashSet::new();
    for rule in rules::commands::COMMAND_RULES {
        assert!(
            seen.insert(rule.name),
            "duplicate command name: '{}'",
            rule.name
        );
    }
}

// ========================================================
// All base_weights match their intent's weight() method
// ========================================================

#[test]
fn base_weights_match_intent_weight() {
    for rule in rules::commands::COMMAND_RULES {
        assert_eq!(
            rule.base_weight,
            rule.intent.weight(),
            "command '{}' has base_weight {} but intent {:?} has weight {}",
            rule.name,
            rule.base_weight,
            rule.intent,
            rule.intent.weight()
        );
    }
}

// ========================================================
// Info commands (weight 0)
// ========================================================

#[test]
fn info_ls() {
    let r = lookup("ls");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
    assert!(r.dangerous_flags.is_empty());
}

#[test]
fn info_pwd() {
    let r = lookup("pwd");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
}

#[test]
fn info_whoami() {
    let r = lookup("whoami");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
    assert!(r.mitre.is_some());
}

#[test]
fn info_hostname() {
    let r = lookup("hostname");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
}

#[test]
fn info_uname() {
    let r = lookup("uname");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
}

#[test]
fn info_date() {
    let r = lookup("date");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
}

#[test]
fn info_uptime() {
    let r = lookup("uptime");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
}

#[test]
fn info_id() {
    let r = lookup("id");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
}

#[test]
fn info_groups() {
    let r = lookup("groups");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
}

#[test]
fn info_echo() {
    let r = lookup("echo");
    assert_eq!(r.intent, Intent::Info);
    assert_eq!(r.base_weight, 0);
}

#[test]
fn info_printf() {
    let r = lookup("printf");
    assert_eq!(r.intent, Intent::Info);
}

#[test]
fn info_which() {
    let r = lookup("which");
    assert_eq!(r.intent, Intent::Info);
}

#[test]
fn info_file() {
    let r = lookup("file");
    assert_eq!(r.intent, Intent::Info);
}

// ========================================================
// Search commands (weight 5)
// ========================================================

#[test]
fn search_find() {
    let r = lookup("find");
    assert_eq!(r.intent, Intent::Search);
    assert_eq!(r.base_weight, 5);
    assert!(!r.dangerous_flags.is_empty());
    // Must have -exec, -execdir, -delete flags
    let flag_names: Vec<&str> = r
        .dangerous_flags
        .iter()
        .flat_map(|f| f.flags.iter().copied())
        .collect();
    assert!(flag_names.contains(&"-exec"));
    assert!(flag_names.contains(&"-execdir"));
    assert!(flag_names.contains(&"-delete"));
}

#[test]
fn search_grep() {
    let r = lookup("grep");
    assert_eq!(r.intent, Intent::Search);
    assert_eq!(r.base_weight, 5);
}

#[test]
fn search_rg() {
    let r = lookup("rg");
    assert_eq!(r.intent, Intent::Search);
}

#[test]
fn search_locate() {
    let r = lookup("locate");
    assert_eq!(r.intent, Intent::Search);
}

// ========================================================
// Read commands (weight 10)
// ========================================================

#[test]
fn read_cat() {
    let r = lookup("cat");
    assert_eq!(r.intent, Intent::Read);
    assert_eq!(r.base_weight, 10);
    assert!(r.capabilities.contains(&BinaryCapability::FileRead));
}

#[test]
fn read_head() {
    let r = lookup("head");
    assert_eq!(r.intent, Intent::Read);
    assert_eq!(r.base_weight, 10);
}

#[test]
fn read_tail() {
    let r = lookup("tail");
    assert_eq!(r.intent, Intent::Read);
}

#[test]
fn read_less() {
    let r = lookup("less");
    assert_eq!(r.intent, Intent::Read);
    assert!(r.capabilities.contains(&BinaryCapability::Shell));
}

#[test]
fn read_base64() {
    let r = lookup("base64");
    assert_eq!(r.intent, Intent::Read);
    assert!(r.mitre.is_some());
}

// ========================================================
// Write commands (weight 30)
// ========================================================

#[test]
fn write_cp() {
    let r = lookup("cp");
    assert_eq!(r.intent, Intent::Write);
    assert_eq!(r.base_weight, 30);
}

#[test]
fn write_mv() {
    let r = lookup("mv");
    assert_eq!(r.intent, Intent::Write);
    assert_eq!(r.base_weight, 30);
    assert_eq!(r.reversibility, Reversibility::HardToReverse);
}

#[test]
fn write_sed_inplace_flag() {
    let r = lookup("sed");
    assert_eq!(r.intent, Intent::Write);
    assert!(!r.dangerous_flags.is_empty());
    let flag_names: Vec<&str> = r
        .dangerous_flags
        .iter()
        .flat_map(|f| f.flags.iter().copied())
        .collect();
    assert!(flag_names.contains(&"-i"));
}

#[test]
fn write_tar_checkpoint_action() {
    let r = lookup("tar");
    assert_eq!(r.intent, Intent::Write);
    assert!(!r.dangerous_flags.is_empty());
    let flag_names: Vec<&str> = r
        .dangerous_flags
        .iter()
        .flat_map(|f| f.flags.iter().copied())
        .collect();
    assert!(flag_names.contains(&"--checkpoint-action=exec="));
}

// ========================================================
// Delete commands (weight 45)
// ========================================================

#[test]
fn delete_rm() {
    let r = lookup("rm");
    assert_eq!(r.intent, Intent::Delete);
    assert_eq!(r.base_weight, 45);
    assert_eq!(r.reversibility, Reversibility::Irreversible);
    assert!(!r.dangerous_flags.is_empty());

    // Must have -rf flag rule
    let has_rf = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"-rf"));
    assert!(has_rf, "rm must have -rf dangerous flag");

    // Must have --no-preserve-root flag rule
    let has_no_preserve = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"--no-preserve-root"));
    assert!(has_no_preserve, "rm must have --no-preserve-root flag");
}

#[test]
fn delete_rmdir() {
    let r = lookup("rmdir");
    assert_eq!(r.intent, Intent::Delete);
    assert_eq!(r.reversibility, Reversibility::Irreversible);
}

#[test]
fn delete_shred() {
    let r = lookup("shred");
    assert_eq!(r.intent, Intent::Delete);
    assert_eq!(r.reversibility, Reversibility::Irreversible);
}

// ========================================================
// Execute commands (weight 50)
// ========================================================

#[test]
fn execute_bash() {
    let r = lookup("bash");
    assert_eq!(r.intent, Intent::Execute);
    assert_eq!(r.base_weight, 50);
    assert!(r.capabilities.contains(&BinaryCapability::Shell));
    assert!(r.mitre.is_some());
}

#[test]
fn execute_python() {
    let r = lookup("python");
    assert_eq!(r.intent, Intent::Execute);
    assert!(r.capabilities.contains(&BinaryCapability::ReverseShell));
}

#[test]
fn execute_node() {
    let r = lookup("node");
    assert_eq!(r.intent, Intent::Execute);
    assert!(r.capabilities.contains(&BinaryCapability::ReverseShell));
}

#[test]
fn execute_eval() {
    let r = lookup("eval");
    assert_eq!(r.intent, Intent::Execute);
}

#[test]
fn execute_exec() {
    let r = lookup("exec");
    assert_eq!(r.intent, Intent::Execute);
}

#[test]
fn execute_source_is_execute() {
    let r = lookup("source");
    assert_eq!(r.intent, Intent::Execute);
}

#[test]
fn execute_perl() {
    let r = lookup("perl");
    assert_eq!(r.intent, Intent::Execute);
    assert!(r.capabilities.contains(&BinaryCapability::ReverseShell));
}

// ========================================================
// Network commands (weight 40)
// ========================================================

#[test]
fn network_curl() {
    let r = lookup("curl");
    assert_eq!(r.intent, Intent::Network);
    assert_eq!(r.base_weight, 40);
    assert!(!r.dangerous_flags.is_empty());

    // Must have POST flag
    let has_post = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"POST") || f.flags.contains(&"-X"));
    assert!(has_post, "curl must have POST-related flag");

    // Must have -d flag
    let has_data = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"-d"));
    assert!(has_data, "curl must have -d flag");

    // Must have -T (upload) flag
    let has_upload = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"-T"));
    assert!(has_upload, "curl must have -T flag");
}

#[test]
fn network_wget() {
    let r = lookup("wget");
    assert_eq!(r.intent, Intent::Network);
    assert!(!r.dangerous_flags.is_empty());

    let has_post_file = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"--post-file"));
    assert!(has_post_file, "wget must have --post-file flag");
}

#[test]
fn network_ssh() {
    let r = lookup("ssh");
    assert_eq!(r.intent, Intent::Network);
    assert!(!r.dangerous_flags.is_empty());

    let has_reverse_tunnel = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"-R"));
    assert!(has_reverse_tunnel, "ssh must have -R flag");

    let has_forward_tunnel = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"-L"));
    assert!(has_forward_tunnel, "ssh must have -L flag");
}

#[test]
fn network_nc() {
    let r = lookup("nc");
    assert_eq!(r.intent, Intent::Network);
    assert!(r.capabilities.contains(&BinaryCapability::ReverseShell));
    assert!(r.capabilities.contains(&BinaryCapability::BindShell));
}

#[test]
fn network_socat() {
    let r = lookup("socat");
    assert_eq!(r.intent, Intent::Network);
    assert!(r.capabilities.contains(&BinaryCapability::ReverseShell));
}

// ========================================================
// Process control (weight 40)
// ========================================================

#[test]
fn process_kill() {
    let r = lookup("kill");
    assert_eq!(r.intent, Intent::ProcessControl);
    assert_eq!(r.base_weight, 40);
    assert_eq!(r.reversibility, Reversibility::Irreversible);
}

#[test]
fn process_killall() {
    let r = lookup("killall");
    assert_eq!(r.intent, Intent::ProcessControl);
}

#[test]
fn process_nohup() {
    let r = lookup("nohup");
    assert_eq!(r.intent, Intent::ProcessControl);
}

// ========================================================
// Privilege commands (weight 55)
// ========================================================

#[test]
fn privilege_sudo() {
    let r = lookup("sudo");
    assert_eq!(r.intent, Intent::Privilege);
    assert_eq!(r.base_weight, 55);
    assert!(r.capabilities.contains(&BinaryCapability::PrivilegeEscalation));
}

#[test]
fn privilege_chmod() {
    let r = lookup("chmod");
    assert_eq!(r.intent, Intent::Privilege);
    assert!(!r.dangerous_flags.is_empty());

    let has_777 = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"777"));
    assert!(has_777, "chmod must have 777 flag");

    let has_setuid = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"+s"));
    assert!(has_setuid, "chmod must have +s flag");

    let has_u_setuid = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"u+s"));
    assert!(has_u_setuid, "chmod must have u+s flag");

    let has_g_setgid = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"g+s"));
    assert!(has_g_setgid, "chmod must have g+s flag");
}

#[test]
fn privilege_chown() {
    let r = lookup("chown");
    assert_eq!(r.intent, Intent::Privilege);
}

#[test]
fn privilege_passwd() {
    let r = lookup("passwd");
    assert_eq!(r.intent, Intent::Privilege);
    assert!(r.mitre.is_some());
}

// ========================================================
// Package managers (weight 35)
// ========================================================

#[test]
fn package_npm() {
    let r = lookup("npm");
    assert_eq!(r.intent, Intent::PackageInstall);
    assert_eq!(r.base_weight, 35);
    assert!(!r.dangerous_flags.is_empty());

    let has_publish = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"publish"));
    assert!(has_publish, "npm must have publish flag");

    let has_run = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"run"));
    assert!(has_run, "npm must have run flag");

    let has_exec = r
        .dangerous_flags
        .iter()
        .any(|f| f.flags.contains(&"exec"));
    assert!(has_exec, "npm must have exec flag");
}

#[test]
fn package_pip() {
    let r = lookup("pip");
    assert_eq!(r.intent, Intent::PackageInstall);
}

#[test]
fn package_cargo() {
    let r = lookup("cargo");
    assert_eq!(r.intent, Intent::PackageInstall);
}

#[test]
fn package_brew() {
    let r = lookup("brew");
    assert_eq!(r.intent, Intent::PackageInstall);
}

// ========================================================
// Git (weight 35)
// ========================================================

#[test]
fn git_mutation() {
    let r = lookup("git");
    assert_eq!(r.intent, Intent::GitMutation);
    assert_eq!(r.base_weight, 35);
    assert!(!r.dangerous_flags.is_empty());
}

#[test]
fn git_force_push() {
    let r = lookup("git");
    let has_force_push = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"push") && f.flags.contains(&"--force")
    });
    assert!(has_force_push, "git must have push --force flag");
}

#[test]
fn git_force_push_short() {
    let r = lookup("git");
    let has_force_push_short = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"push") && f.flags.contains(&"-f")
    });
    assert!(has_force_push_short, "git must have push -f flag");
}

#[test]
fn git_force_with_lease() {
    let r = lookup("git");
    let found = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"push") && f.flags.contains(&"--force-with-lease")
    });
    assert!(found, "git must have push --force-with-lease flag");
}

#[test]
fn git_reset_hard() {
    let r = lookup("git");
    let found = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"reset") && f.flags.contains(&"--hard")
    });
    assert!(found, "git must have reset --hard flag");
}

#[test]
fn git_clean_fd() {
    let r = lookup("git");
    let found = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"clean") && f.flags.contains(&"-fd")
    });
    assert!(found, "git must have clean -fd flag");
}

#[test]
fn git_clean_fxd() {
    let r = lookup("git");
    let found = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"clean") && f.flags.contains(&"-fxd")
    });
    assert!(found, "git must have clean -fxd flag");
}

#[test]
fn git_checkout_discard() {
    let r = lookup("git");
    let found = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"checkout") && f.flags.contains(&"--") && f.flags.contains(&".")
    });
    assert!(found, "git must have checkout -- . flag");
}

#[test]
fn git_branch_force_delete() {
    let r = lookup("git");
    let found = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"branch") && f.flags.contains(&"-D")
    });
    assert!(found, "git must have branch -D flag");
}

// ========================================================
// Environment (weight 40)
// ========================================================

#[test]
fn env_export() {
    let r = lookup("export");
    assert_eq!(r.intent, Intent::EnvModify);
    assert_eq!(r.base_weight, 40);
}

#[test]
fn env_unset() {
    let r = lookup("unset");
    assert_eq!(r.intent, Intent::EnvModify);
}

#[test]
fn env_alias() {
    let r = lookup("alias");
    assert_eq!(r.intent, Intent::EnvModify);
}

// ========================================================
// Container / orchestration
// ========================================================

#[test]
fn docker_privileged() {
    let r = lookup("docker");
    assert_eq!(r.intent, Intent::Execute);
    assert!(!r.dangerous_flags.is_empty());
    let has_priv = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"--privileged")
    });
    assert!(has_priv, "docker must have --privileged flag");
}

#[test]
fn kubectl_delete() {
    let r = lookup("kubectl");
    assert_eq!(r.intent, Intent::Execute);
    let has_delete = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"delete")
    });
    assert!(has_delete, "kubectl must have delete flag");
    let has_exec = r.dangerous_flags.iter().any(|f| {
        f.flags.contains(&"exec")
    });
    assert!(has_exec, "kubectl must have exec flag");
}

// ========================================================
// Every command in the table returns Some with correct intent
// ========================================================

#[test]
fn every_command_is_lookupable() {
    for rule in rules::commands::COMMAND_RULES {
        let found = rules::lookup_command(rule.name);
        assert!(
            found.is_some(),
            "lookup_command('{}') should return Some",
            rule.name
        );
        let found = found.unwrap();
        assert_eq!(
            found.intent, rule.intent,
            "intent mismatch for '{}'",
            rule.name
        );
    }
}

// ========================================================
// Commands with dangerous_flags are non-empty for expected commands
// ========================================================

#[test]
fn commands_with_flags_are_correct() {
    let expected_flagged = &[
        "rm", "curl", "wget", "git", "chmod", "find", "ssh", "npm",
        "docker", "kubectl", "tar", "sed",
    ];
    for &name in expected_flagged {
        let r = lookup(name);
        assert!(
            !r.dangerous_flags.is_empty(),
            "'{}' should have non-empty dangerous_flags",
            name
        );
    }
}

// ========================================================
// Verify rule count is at least 80
// ========================================================

#[test]
fn at_least_80_command_rules() {
    assert!(
        rules::commands::COMMAND_RULES.len() >= 80,
        "expected at least 80 rules, got {}",
        rules::commands::COMMAND_RULES.len()
    );
}

// ========================================================
// All FlagRule risk_factors are valid enum variants (compile-time checked)
// and all modifiers are positive
// ========================================================

#[test]
fn all_flag_modifiers_are_positive() {
    for rule in rules::commands::COMMAND_RULES {
        for flag in rule.dangerous_flags {
            assert!(
                flag.modifier > 0,
                "command '{}' has a flag with non-positive modifier: {}",
                rule.name,
                flag.modifier
            );
        }
    }
}

#[test]
fn all_flag_descriptions_non_empty() {
    for rule in rules::commands::COMMAND_RULES {
        for flag in rule.dangerous_flags {
            assert!(
                !flag.description.is_empty(),
                "command '{}' has a flag with empty description",
                rule.name
            );
        }
    }
}

#[test]
fn all_flag_arrays_non_empty() {
    for rule in rules::commands::COMMAND_RULES {
        for flag in rule.dangerous_flags {
            assert!(
                !flag.flags.is_empty(),
                "command '{}' has a FlagRule with empty flags array",
                rule.name
            );
        }
    }
}

// ========================================================
// Specific additional commands exist
// ========================================================

#[test]
fn additional_commands_exist() {
    let expected = &[
        "xargs", "dd", "crontab", "sort", "ps", "top", "lsof",
        "netstat", "mount", "systemctl", "iptables", "openssl",
    ];
    for &name in expected {
        assert!(
            rules::lookup_command(name).is_some(),
            "expected rule for '{}'",
            name
        );
    }
}
