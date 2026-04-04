use sh_guard_core::test_internals::context;
use sh_guard_core::types::*;

// ========================================================
// Helper: create contexts
// ========================================================

fn ctx_full() -> ClassifyContext {
    ClassifyContext {
        cwd: Some("/home/user/project".into()),
        project_root: Some("/home/user/project".into()),
        home_dir: Some("/home/user".into()),
        protected_paths: vec!["important.db".into(), "production.key".into()],
        shell: Shell::Bash,
    }
}

fn ctx_minimal() -> ClassifyContext {
    ClassifyContext {
        cwd: None,
        project_root: None,
        home_dir: None,
        protected_paths: vec![],
        shell: Shell::Bash,
    }
}

// ========================================================
// resolve_scope: root
// ========================================================

#[test]
fn scope_root_slash() {
    assert_eq!(context::resolve_scope("/", None), TargetScope::Root);
}

#[test]
fn scope_root_with_context() {
    let ctx = ctx_full();
    assert_eq!(context::resolve_scope("/", Some(&ctx)), TargetScope::Root);
}

// ========================================================
// resolve_scope: tilde (home)
// ========================================================

#[test]
fn scope_tilde_is_home() {
    assert_eq!(context::resolve_scope("~", None), TargetScope::Home);
}

#[test]
fn scope_tilde_slash_is_home() {
    assert_eq!(context::resolve_scope("~/", None), TargetScope::Home);
}

#[test]
fn scope_tilde_subpath_is_single_file() {
    // ~/something is not exactly "home", it's a file within home
    assert_eq!(
        context::resolve_scope("~/something", None),
        TargetScope::SingleFile
    );
}

// ========================================================
// resolve_scope: home via context
// ========================================================

#[test]
fn scope_home_dir_exact_match() {
    let ctx = ctx_full();
    assert_eq!(
        context::resolve_scope("/home/user", Some(&ctx)),
        TargetScope::Home
    );
}

#[test]
fn scope_home_dir_trailing_slash() {
    let ctx = ctx_full();
    assert_eq!(
        context::resolve_scope("/home/user/", Some(&ctx)),
        TargetScope::Home
    );
}

// ========================================================
// resolve_scope: system directories
// ========================================================

#[test]
fn scope_etc_passwd_is_system() {
    assert_eq!(
        context::resolve_scope("/etc/passwd", None),
        TargetScope::System
    );
}

#[test]
fn scope_usr_bin_is_system() {
    assert_eq!(
        context::resolve_scope("/usr/bin/ls", None),
        TargetScope::System
    );
}

#[test]
fn scope_var_log_is_system() {
    assert_eq!(
        context::resolve_scope("/var/log/syslog", None),
        TargetScope::System
    );
}

#[test]
fn scope_proc_is_system() {
    assert_eq!(
        context::resolve_scope("/proc/1/environ", None),
        TargetScope::System
    );
}

#[test]
fn scope_boot_is_system() {
    assert_eq!(
        context::resolve_scope("/boot/vmlinuz", None),
        TargetScope::System
    );
}

#[test]
fn scope_sys_is_system() {
    assert_eq!(
        context::resolve_scope("/sys/class", None),
        TargetScope::System
    );
}

#[test]
fn scope_opt_is_system() {
    assert_eq!(
        context::resolve_scope("/opt/app/bin", None),
        TargetScope::System
    );
}

// ========================================================
// resolve_scope: normal files
// ========================================================

#[test]
fn scope_tmp_file_is_single_file() {
    assert_eq!(
        context::resolve_scope("/tmp/file.txt", None),
        TargetScope::SingleFile
    );
}

#[test]
fn scope_relative_path_is_single_file() {
    assert_eq!(
        context::resolve_scope("./src/main.rs", None),
        TargetScope::SingleFile
    );
}

#[test]
fn scope_bare_filename_is_single_file() {
    // No leading / or ~ so not system or home
    assert_eq!(
        context::resolve_scope("file.txt", None),
        TargetScope::SingleFile
    );
}

// ========================================================
// resolve_sensitivity: .env
// ========================================================

#[test]
fn sensitivity_env_file() {
    assert_eq!(
        context::resolve_sensitivity(".env", None),
        Sensitivity::Secrets
    );
}

#[test]
fn sensitivity_env_local() {
    assert_eq!(
        context::resolve_sensitivity(".env.local", None),
        Sensitivity::Secrets
    );
}

// ========================================================
// resolve_sensitivity: SSH keys
// ========================================================

#[test]
fn sensitivity_ssh_id_rsa() {
    assert_eq!(
        context::resolve_sensitivity(".ssh/id_rsa", None),
        Sensitivity::Secrets
    );
}

#[test]
fn sensitivity_ssh_dir() {
    assert_eq!(
        context::resolve_sensitivity(".ssh", None),
        Sensitivity::Secrets
    );
}

// ========================================================
// resolve_sensitivity: system files
// ========================================================

#[test]
fn sensitivity_etc_passwd() {
    assert_eq!(
        context::resolve_sensitivity("/etc/passwd", None),
        Sensitivity::System
    );
}

#[test]
fn sensitivity_etc_shadow() {
    assert_eq!(
        context::resolve_sensitivity("/etc/shadow", None),
        Sensitivity::System
    );
}

// ========================================================
// resolve_sensitivity: normal files
// ========================================================

#[test]
fn sensitivity_normal_txt() {
    assert_eq!(
        context::resolve_sensitivity("normal.txt", None),
        Sensitivity::Normal
    );
}

#[test]
fn sensitivity_normal_rs() {
    assert_eq!(
        context::resolve_sensitivity("src/main.rs", None),
        Sensitivity::Normal
    );
}

// ========================================================
// resolve_sensitivity: user-protected paths
// ========================================================

#[test]
fn sensitivity_user_protected_path() {
    let ctx = ctx_full();
    assert_eq!(
        context::resolve_sensitivity("important.db", Some(&ctx)),
        Sensitivity::Protected
    );
}

#[test]
fn sensitivity_user_protected_path_in_subdir() {
    let ctx = ctx_full();
    assert_eq!(
        context::resolve_sensitivity("/some/dir/production.key", Some(&ctx)),
        Sensitivity::Protected
    );
}

#[test]
fn sensitivity_user_protected_overrides_normal() {
    let ctx = ClassifyContext {
        cwd: None,
        project_root: None,
        home_dir: None,
        protected_paths: vec!["normal.txt".into()],
        shell: Shell::Bash,
    };
    assert_eq!(
        context::resolve_sensitivity("normal.txt", Some(&ctx)),
        Sensitivity::Protected
    );
}

#[test]
fn sensitivity_without_context_falls_to_builtin() {
    // .bashrc is Config sensitivity in built-in rules
    assert_eq!(
        context::resolve_sensitivity(".bashrc", None),
        Sensitivity::Config
    );
}

// ========================================================
// context_adjustment: no context
// ========================================================

#[test]
fn adjustment_no_context_returns_5() {
    assert_eq!(
        context::context_adjustment("/any/path", &Intent::Write, None),
        5
    );
}

#[test]
fn adjustment_no_context_returns_5_for_read() {
    assert_eq!(
        context::context_adjustment("/any/path", &Intent::Read, None),
        5
    );
}

// ========================================================
// context_adjustment: inside project
// ========================================================

#[test]
fn adjustment_inside_project_write_negative() {
    let ctx = ctx_full();
    let adj =
        context::context_adjustment("/home/user/project/src/file.rs", &Intent::Write, Some(&ctx));
    assert!(
        adj < 0,
        "write inside project should be negative, got {}",
        adj
    );
}

#[test]
fn adjustment_inside_project_read_zero() {
    let ctx = ctx_full();
    let adj =
        context::context_adjustment("/home/user/project/src/file.rs", &Intent::Read, Some(&ctx));
    // Read inside project, but still inside home; cwd starts with home so no home penalty
    // No project escaping penalty, no protected paths match
    assert_eq!(adj, 0);
}

#[test]
fn adjustment_inside_build_dir_extra_negative() {
    let ctx = ctx_full();
    let adj = context::context_adjustment(
        "/home/user/project/target/debug/build",
        &Intent::Delete,
        Some(&ctx),
    );
    // -10 for project + -15 for build dir = -25
    assert_eq!(adj, -25);
}

#[test]
fn adjustment_inside_node_modules_extra_negative() {
    let ctx = ctx_full();
    let adj = context::context_adjustment(
        "/home/user/project/node_modules/pkg/index.js",
        &Intent::Write,
        Some(&ctx),
    );
    assert_eq!(adj, -25);
}

#[test]
fn adjustment_inside_dist_dir() {
    let ctx = ctx_full();
    let adj = context::context_adjustment(
        "/home/user/project/dist/bundle.js",
        &Intent::Delete,
        Some(&ctx),
    );
    assert_eq!(adj, -25);
}

// ========================================================
// context_adjustment: outside project
// ========================================================

#[test]
fn adjustment_outside_project_write_positive() {
    let ctx = ctx_full();
    let adj = context::context_adjustment("/tmp/outside", &Intent::Write, Some(&ctx));
    // +20 for escaping project boundary
    assert!(
        adj > 0,
        "write outside project should be positive, got {}",
        adj
    );
}

#[test]
fn adjustment_outside_project_delete_positive() {
    let ctx = ctx_full();
    let adj = context::context_adjustment("/etc/hosts", &Intent::Delete, Some(&ctx));
    assert!(
        adj > 0,
        "delete outside project should be positive, got {}",
        adj
    );
}

// ========================================================
// context_adjustment: protected paths
// ========================================================

#[test]
fn adjustment_protected_path_adds_25() {
    let ctx = ctx_full();
    let adj =
        context::context_adjustment("/home/user/project/important.db", &Intent::Read, Some(&ctx));
    // Inside project (no write/delete bonus), but protected path = +25
    assert!(adj >= 25, "protected path should add 25, got {}", adj);
}

#[test]
fn adjustment_protected_path_write_inside_project() {
    let ctx = ctx_full();
    let adj = context::context_adjustment(
        "/home/user/project/important.db",
        &Intent::Write,
        Some(&ctx),
    );
    // -10 inside project + 25 protected = 15
    assert_eq!(adj, 15);
}

// ========================================================
// context_adjustment: home directory targeting
// ========================================================

#[test]
fn adjustment_targets_home_from_outside() {
    let ctx = ClassifyContext {
        cwd: Some("/tmp".into()),
        project_root: None,
        home_dir: Some("/home/user".into()),
        protected_paths: vec![],
        shell: Shell::Bash,
    };
    let adj = context::context_adjustment("/home/user/.bashrc", &Intent::Read, Some(&ctx));
    // cwd=/tmp does not start with /home/user, so +15 home penalty
    assert!(
        adj >= 15,
        "should penalize home access from outside, got {}",
        adj
    );
}

#[test]
fn adjustment_targets_home_exact() {
    let ctx = ClassifyContext {
        cwd: Some("/home/user/project".into()),
        project_root: None,
        home_dir: Some("/home/user".into()),
        protected_paths: vec![],
        shell: Shell::Bash,
    };
    let adj = context::context_adjustment("/home/user", &Intent::Read, Some(&ctx));
    // cwd starts with /home/user, but path == home_normalized triggers +15
    assert!(
        adj >= 15,
        "targeting home dir exactly should penalize, got {}",
        adj
    );
}

// ========================================================
// context_adjustment: minimal context
// ========================================================

#[test]
fn adjustment_minimal_context_returns_zero_for_read() {
    let ctx = ctx_minimal();
    let adj = context::context_adjustment("/any/path", &Intent::Read, Some(&ctx));
    assert_eq!(adj, 0);
}

// ========================================================
// normalize_path
// ========================================================

#[test]
fn normalize_trailing_slash() {
    assert_eq!(context::normalize_path("/home/user/"), "/home/user");
}

#[test]
fn normalize_multiple_trailing_slashes() {
    assert_eq!(context::normalize_path("/home/user///"), "/home/user");
}

#[test]
fn normalize_double_slashes() {
    assert_eq!(
        context::normalize_path("/home//user//file"),
        "/home/user/file"
    );
}

#[test]
fn normalize_root_stays_root() {
    assert_eq!(context::normalize_path("/"), "/");
}

#[test]
fn normalize_root_with_trailing_slash() {
    // Multiple slashes collapse to one /
    assert_eq!(context::normalize_path("//"), "/");
}

#[test]
fn normalize_tilde() {
    // Tilde is not resolved, just normalized
    assert_eq!(context::normalize_path("~/"), "~");
}

#[test]
fn normalize_plain_path() {
    assert_eq!(
        context::normalize_path("/home/user/file"),
        "/home/user/file"
    );
}

#[test]
fn normalize_empty_string() {
    assert_eq!(context::normalize_path(""), "");
}
