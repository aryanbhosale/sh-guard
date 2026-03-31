use sh_guard_core::test_internals::rules;
use sh_guard_core::types::*;
use std::collections::HashSet;

// ========================================================
// Helper
// ========================================================

fn must_match(path: &str) -> (Sensitivity, &'static str) {
    rules::paths::match_sensitivity(path)
        .unwrap_or_else(|| panic!("expected '{}' to match a sensitive path rule", path))
}

fn must_not_match(path: &str) {
    assert!(
        rules::paths::match_sensitivity(path).is_none(),
        "expected '{}' NOT to match any sensitive path rule",
        path
    );
}

// ========================================================
// No duplicate patterns in the table
// ========================================================

#[test]
fn no_duplicate_patterns() {
    let mut seen = HashSet::new();
    for rule in rules::paths::SENSITIVE_PATHS {
        assert!(
            seen.insert(rule.pattern),
            "duplicate path pattern: '{}'",
            rule.pattern
        );
    }
}

// ========================================================
// Rule count
// ========================================================

#[test]
fn at_least_51_path_rules() {
    assert!(
        rules::paths::SENSITIVE_PATHS.len() >= 51,
        "expected at least 51 path rules, got {}",
        rules::paths::SENSITIVE_PATHS.len()
    );
}

// ========================================================
// All descriptions are non-empty
// ========================================================

#[test]
fn all_descriptions_non_empty() {
    for rule in rules::paths::SENSITIVE_PATHS {
        assert!(
            !rule.description.is_empty(),
            "path rule '{}' has an empty description",
            rule.pattern
        );
    }
}

// ========================================================
// Secrets — exact pattern matches
// ========================================================

#[test]
fn env_file_matches() {
    let (s, _) = must_match(".env");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn env_variant_matches() {
    let (s, _) = must_match(".env.production");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn env_local_variant_matches() {
    let (s, _) = must_match(".env.local");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn ssh_directory_matches() {
    let (s, _) = must_match(".ssh");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn ssh_id_rsa_matches() {
    let (s, _) = must_match(".ssh/id_rsa");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn ssh_authorized_keys_matches() {
    let (s, _) = must_match(".ssh/authorized_keys");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn aws_credentials_matches() {
    let (s, _) = must_match(".aws/credentials");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn aws_config_matches() {
    let (s, _) = must_match(".aws/config");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn gnupg_matches() {
    let (s, _) = must_match(".gnupg/secring.gpg");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn credentials_json_matches() {
    let (s, _) = must_match("credentials.json");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn pem_file_matches() {
    let (s, _) = must_match("server.pem");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn key_file_matches() {
    let (s, _) = must_match("private.key");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn p12_file_matches() {
    let (s, _) = must_match("cert.p12");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn pfx_file_matches() {
    let (s, _) = must_match("cert.pfx");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn netrc_matches() {
    let (s, _) = must_match(".netrc");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn npmrc_matches() {
    let (s, _) = must_match(".npmrc");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn pypirc_matches() {
    let (s, _) = must_match(".pypirc");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn docker_config_json_matches() {
    let (s, _) = must_match(".docker/config.json");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn kube_config_matches() {
    let (s, _) = must_match(".kube/config");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn gcloud_matches() {
    let (s, _) = must_match(".gcloud/credentials.db");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn id_rsa_basename_matches() {
    let (s, _) = must_match("id_rsa");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn id_ed25519_matches() {
    let (s, _) = must_match("id_ed25519");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn id_ecdsa_matches() {
    let (s, _) = must_match("id_ecdsa");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn secret_file_matches() {
    let (s, _) = must_match("app.secret");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn secrets_file_matches() {
    let (s, _) = must_match("db.secrets");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn htpasswd_matches() {
    let (s, _) = must_match(".htpasswd");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn token_json_matches() {
    let (s, _) = must_match("token.json");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn terraform_state_matches() {
    let (s, _) = must_match("terraform.tfstate");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn terraform_dir_matches() {
    let (s, _) = must_match(".terraform/modules.json");
    assert_eq!(s, Sensitivity::Secrets);
}

// ========================================================
// System — absolute path patterns
// ========================================================

#[test]
fn etc_passwd_matches() {
    let (s, _) = must_match("/etc/passwd");
    assert_eq!(s, Sensitivity::System);
}

#[test]
fn etc_shadow_matches() {
    let (s, _) = must_match("/etc/shadow");
    assert_eq!(s, Sensitivity::System);
}

#[test]
fn etc_sudoers_matches() {
    let (s, _) = must_match("/etc/sudoers");
    assert_eq!(s, Sensitivity::System);
}

#[test]
fn etc_hosts_matches() {
    let (s, _) = must_match("/etc/hosts");
    assert_eq!(s, Sensitivity::System);
}

#[test]
fn etc_resolv_conf_matches() {
    let (s, _) = must_match("/etc/resolv.conf");
    assert_eq!(s, Sensitivity::System);
}

#[test]
fn etc_crontab_matches() {
    let (s, _) = must_match("/etc/crontab");
    assert_eq!(s, Sensitivity::System);
}

#[test]
fn etc_ssh_config_matches() {
    let (s, _) = must_match("/etc/ssh/sshd_config");
    assert_eq!(s, Sensitivity::System);
}

#[test]
fn proc_environ_matches() {
    let (s, _) = must_match("/proc/1234/environ");
    assert_eq!(s, Sensitivity::System);
}

#[test]
fn proc_self_environ_matches() {
    let (s, _) = must_match("/proc/self/environ");
    assert_eq!(s, Sensitivity::System);
}

// ========================================================
// Config patterns
// ========================================================

#[test]
fn gitconfig_matches() {
    let (s, _) = must_match(".gitconfig");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn git_config_matches() {
    let (s, _) = must_match(".git/config");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn bashrc_matches() {
    let (s, _) = must_match(".bashrc");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn bash_profile_matches() {
    let (s, _) = must_match(".bash_profile");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn zshrc_matches() {
    let (s, _) = must_match(".zshrc");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn zprofile_matches() {
    let (s, _) = must_match(".zprofile");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn profile_matches() {
    let (s, _) = must_match(".profile");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn vimrc_matches() {
    let (s, _) = must_match(".vimrc");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn claude_config_matches() {
    let (s, _) = must_match(".claude/settings.json");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn cursor_config_matches() {
    let (s, _) = must_match(".cursor/rules");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn vscode_config_matches() {
    let (s, _) = must_match(".vscode/settings.json");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn xdg_config_matches() {
    let (s, _) = must_match(".config/nvim/init.vim");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn makefile_matches() {
    let (s, _) = must_match("Makefile");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn dockerfile_matches() {
    let (s, _) = must_match("Dockerfile");
    assert_eq!(s, Sensitivity::Config);
}

#[test]
fn docker_compose_matches() {
    let (s, _) = must_match("docker-compose.yml");
    assert_eq!(s, Sensitivity::Config);
}

// ========================================================
// Basename matching — basename extracted from full path
// ========================================================

#[test]
fn basename_id_rsa_in_ssh_dir() {
    let (s, _) = must_match("~/.ssh/id_rsa");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn basename_pem_in_nested_dir() {
    let (s, _) = must_match("/opt/certs/server.pem");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn basename_key_in_nested_dir() {
    let (s, _) = must_match("/home/user/ssl/private.key");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn basename_credentials_json_in_project() {
    let (s, _) = must_match("project/config/credentials.json");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn basename_env_in_project() {
    let (s, _) = must_match("myproject/.env");
    assert_eq!(s, Sensitivity::Secrets);
}

// ========================================================
// Relative path with ./ prefix
// ========================================================

#[test]
fn dotslash_env_matches() {
    let (s, _) = must_match("./.env");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn dotslash_ssh_matches() {
    let (s, _) = must_match("./.ssh/id_rsa");
    assert_eq!(s, Sensitivity::Secrets);
}

// ========================================================
// Non-matching — similar but should NOT match
// ========================================================

#[test]
fn envrc_does_not_match_env() {
    must_not_match(".envrc");
}

#[test]
fn env_without_dot_does_not_match() {
    must_not_match("env");
}

#[test]
fn random_txt_does_not_match() {
    must_not_match("readme.txt");
}

#[test]
fn random_rs_does_not_match() {
    must_not_match("src/main.rs");
}

#[test]
fn cargo_toml_does_not_match() {
    must_not_match("Cargo.toml");
}

#[test]
fn node_modules_does_not_match() {
    must_not_match("node_modules/package/index.js");
}

#[test]
fn ssh_substring_does_not_match() {
    // ".sshrc" should not match ".ssh"
    must_not_match(".sshrc");
}

#[test]
fn etc_hostname_does_not_match() {
    // "/etc/hostname" is not in the rules
    must_not_match("/etc/hostname");
}

// ========================================================
// match_sensitivity returns highest sensitivity
// ========================================================

#[test]
fn highest_sensitivity_wins() {
    // ".ssh/id_rsa" matches both ".ssh/*" (Secrets) and "id_rsa" (Secrets)
    // Both are Secrets, so we get Secrets
    let (s, _) = must_match(".ssh/id_rsa");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn secrets_beats_config_for_terraform() {
    // ".terraform/foo" matches ".terraform/*" (Secrets)
    let (s, _) = must_match(".terraform/terraform.tfstate");
    assert_eq!(s, Sensitivity::Secrets);
}

// ========================================================
// Glob matching edge cases
// ========================================================

#[test]
fn glob_star_matches_any_extension() {
    // "*.pem" should match anything ending in .pem
    let (s, _) = must_match("anything.pem");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn glob_env_variant_matches_staging() {
    let (s, _) = must_match(".env.staging");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn glob_env_variant_matches_test() {
    let (s, _) = must_match(".env.test");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn proc_wildcard_matches_pid() {
    let (s, _) = must_match("/proc/42/environ");
    assert_eq!(s, Sensitivity::System);
}

// ========================================================
// Directory patterns with deeper paths
// ========================================================

#[test]
fn docker_config_in_home() {
    let (s, _) = must_match("home/user/.docker/config.json");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn kube_config_in_home() {
    let (s, _) = must_match("home/user/.kube/config");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn aws_credentials_in_home() {
    let (s, _) = must_match("home/user/.aws/credentials");
    assert_eq!(s, Sensitivity::Secrets);
}

#[test]
fn git_config_in_repo() {
    let (s, _) = must_match("my-repo/.git/config");
    assert_eq!(s, Sensitivity::Config);
}

// ========================================================
// Every SENSITIVE_PATHS entry has a matching test input
// ========================================================

#[test]
fn every_rule_has_at_least_one_matching_input() {
    // For each rule, construct a plausible path that should match
    let test_inputs: Vec<(&str, &str)> = vec![
        (".env", ".env"),
        (".env.*", ".env.local"),
        (".ssh", ".ssh"),
        (".ssh/*", ".ssh/id_rsa"),
        (".aws/credentials", ".aws/credentials"),
        (".aws/config", ".aws/config"),
        (".gnupg/*", ".gnupg/secring.gpg"),
        ("credentials.json", "credentials.json"),
        ("*.pem", "server.pem"),
        ("*.key", "private.key"),
        ("*.p12", "cert.p12"),
        ("*.pfx", "cert.pfx"),
        (".netrc", ".netrc"),
        (".npmrc", ".npmrc"),
        (".pypirc", ".pypirc"),
        (".docker/config.json", ".docker/config.json"),
        (".kube/config", ".kube/config"),
        (".gcloud/*", ".gcloud/creds"),
        ("id_rsa", "id_rsa"),
        ("id_ed25519", "id_ed25519"),
        ("id_ecdsa", "id_ecdsa"),
        ("*.secret", "app.secret"),
        ("*.secrets", "db.secrets"),
        (".htpasswd", ".htpasswd"),
        ("token.json", "token.json"),
        ("/etc/passwd", "/etc/passwd"),
        ("/etc/shadow", "/etc/shadow"),
        ("/etc/sudoers", "/etc/sudoers"),
        ("/etc/hosts", "/etc/hosts"),
        ("/etc/resolv.conf", "/etc/resolv.conf"),
        ("/etc/crontab", "/etc/crontab"),
        ("/etc/ssh/*", "/etc/ssh/sshd_config"),
        ("/proc/*/environ", "/proc/123/environ"),
        ("/proc/self/environ", "/proc/self/environ"),
        (".gitconfig", ".gitconfig"),
        (".git/config", ".git/config"),
        (".bashrc", ".bashrc"),
        (".bash_profile", ".bash_profile"),
        (".zshrc", ".zshrc"),
        (".zprofile", ".zprofile"),
        (".profile", ".profile"),
        (".vimrc", ".vimrc"),
        (".claude/*", ".claude/settings.json"),
        (".cursor/*", ".cursor/rules"),
        (".vscode/*", ".vscode/settings.json"),
        (".config/*", ".config/foo"),
        ("Makefile", "Makefile"),
        ("Dockerfile", "Dockerfile"),
        ("docker-compose.yml", "docker-compose.yml"),
        (".terraform/*", ".terraform/modules.json"),
        ("terraform.tfstate", "terraform.tfstate"),
    ];

    for (pattern, input) in &test_inputs {
        let result = rules::paths::match_sensitivity(input);
        assert!(
            result.is_some(),
            "pattern '{}' should match input '{}' but got None",
            pattern,
            input
        );
    }
}
