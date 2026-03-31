use sh_guard_core::test_internals::rules;
use sh_guard_core::types::BinaryCapability;
use std::collections::HashSet;

// ========================================================
// Helper
// ========================================================

fn caps(name: &str) -> &'static [BinaryCapability] {
    rules::gtfobins::lookup_capabilities(name)
}

fn has_cap(name: &str, cap: BinaryCapability) -> bool {
    caps(name).contains(&cap)
}

// ========================================================
// No duplicate entry names
// ========================================================

#[test]
fn no_duplicate_entry_names() {
    let mut seen = HashSet::new();
    for e in rules::gtfobins::GTFOBINS {
        assert!(
            seen.insert(e.name),
            "duplicate GTFOBins entry name: '{}'",
            e.name
        );
    }
}

// ========================================================
// Entry count (60+)
// ========================================================

#[test]
fn entry_count_at_least_60() {
    assert!(
        rules::gtfobins::GTFOBINS.len() >= 60,
        "expected at least 60 entries, got {}",
        rules::gtfobins::GTFOBINS.len()
    );
}

// ========================================================
// Every BinaryCapability variant appears at least once
// ========================================================

#[test]
fn every_capability_variant_represented() {
    let all_caps: HashSet<BinaryCapability> = rules::gtfobins::GTFOBINS
        .iter()
        .flat_map(|e| e.capabilities.iter().copied())
        .collect();

    let expected = [
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
    ];

    for cap in &expected {
        assert!(
            all_caps.contains(cap),
            "BinaryCapability::{:?} not found in any GTFOBins entry",
            cap
        );
    }
}

// ========================================================
// Path stripping works
// ========================================================

#[test]
fn path_stripping_usr_bin() {
    assert!(!caps("/usr/bin/vim").is_empty());
}

#[test]
fn path_stripping_usr_local_bin() {
    assert!(!caps("/usr/local/bin/python3").is_empty());
}

#[test]
fn path_stripping_deep_path() {
    assert!(!caps("/some/nested/path/curl").is_empty());
}

// ========================================================
// Unknown binary returns empty
// ========================================================

#[test]
fn unknown_binary_returns_empty() {
    assert!(caps("nonexistent_binary_xyz").is_empty());
}

#[test]
fn empty_name_returns_empty() {
    assert!(caps("").is_empty());
}

// ========================================================
// Shell-capable binaries
// ========================================================

#[test]
fn vim_has_shell() {
    assert!(has_cap("vim", BinaryCapability::Shell));
}

#[test]
fn vi_has_shell() {
    assert!(has_cap("vi", BinaryCapability::Shell));
}

#[test]
fn emacs_has_shell() {
    assert!(has_cap("emacs", BinaryCapability::Shell));
}

#[test]
fn less_has_shell() {
    assert!(has_cap("less", BinaryCapability::Shell));
}

#[test]
fn man_has_shell() {
    assert!(has_cap("man", BinaryCapability::Shell));
}

#[test]
fn gdb_has_shell() {
    assert!(has_cap("gdb", BinaryCapability::Shell));
}

// ========================================================
// Command-capable binaries
// ========================================================

#[test]
fn find_has_command() {
    assert!(has_cap("find", BinaryCapability::Command));
}

#[test]
fn xargs_has_command() {
    assert!(has_cap("xargs", BinaryCapability::Command));
}

#[test]
fn env_has_command() {
    assert!(has_cap("env", BinaryCapability::Command));
}

// ========================================================
// File read binaries
// ========================================================

#[test]
fn base64_has_file_read() {
    assert!(has_cap("base64", BinaryCapability::FileRead));
}

#[test]
fn head_has_file_read() {
    assert!(has_cap("head", BinaryCapability::FileRead));
}

#[test]
fn tail_has_file_read() {
    assert!(has_cap("tail", BinaryCapability::FileRead));
}

#[test]
fn strings_has_file_read() {
    assert!(has_cap("strings", BinaryCapability::FileRead));
}

// ========================================================
// File write binaries
// ========================================================

#[test]
fn tee_has_file_write() {
    assert!(has_cap("tee", BinaryCapability::FileWrite));
}

#[test]
fn cp_has_file_write() {
    assert!(has_cap("cp", BinaryCapability::FileWrite));
}

#[test]
fn dd_has_file_write() {
    assert!(has_cap("dd", BinaryCapability::FileWrite));
}

// ========================================================
// Network binaries
// ========================================================

#[test]
fn curl_has_download() {
    assert!(has_cap("curl", BinaryCapability::Download));
}

#[test]
fn wget_has_download() {
    assert!(has_cap("wget", BinaryCapability::Download));
}

#[test]
fn curl_has_upload() {
    assert!(has_cap("curl", BinaryCapability::Upload));
}

#[test]
fn scp_has_upload_and_download() {
    assert!(has_cap("scp", BinaryCapability::Upload));
    assert!(has_cap("scp", BinaryCapability::Download));
}

// ========================================================
// Reverse shell binaries
// ========================================================

#[test]
fn nc_has_reverse_shell() {
    assert!(has_cap("nc", BinaryCapability::ReverseShell));
}

#[test]
fn socat_has_reverse_shell() {
    assert!(has_cap("socat", BinaryCapability::ReverseShell));
}

#[test]
fn python_has_reverse_shell() {
    assert!(has_cap("python", BinaryCapability::ReverseShell));
}

#[test]
fn telnet_has_reverse_shell() {
    assert!(has_cap("telnet", BinaryCapability::ReverseShell));
}

// ========================================================
// Bind shell binaries
// ========================================================

#[test]
fn nc_has_bind_shell() {
    assert!(has_cap("nc", BinaryCapability::BindShell));
}

#[test]
fn ncat_has_bind_shell() {
    assert!(has_cap("ncat", BinaryCapability::BindShell));
}

// ========================================================
// Privilege escalation
// ========================================================

#[test]
fn docker_has_priv_esc() {
    assert!(has_cap("docker", BinaryCapability::PrivilegeEscalation));
}

#[test]
fn pkexec_has_priv_esc() {
    assert!(has_cap("pkexec", BinaryCapability::PrivilegeEscalation));
}

#[test]
fn doas_has_priv_esc() {
    assert!(has_cap("doas", BinaryCapability::PrivilegeEscalation));
}

// ========================================================
// Library loading
// ========================================================

#[test]
fn ld_so_has_library_load() {
    assert!(has_cap("ld.so", BinaryCapability::LibraryLoad));
}

// ========================================================
// Multi-capability entries
// ========================================================

#[test]
fn python3_has_multiple_capabilities() {
    let c = caps("python3");
    assert!(c.contains(&BinaryCapability::Shell));
    assert!(c.contains(&BinaryCapability::Command));
    assert!(c.contains(&BinaryCapability::ReverseShell));
    assert!(c.contains(&BinaryCapability::FileRead));
    assert!(c.contains(&BinaryCapability::FileWrite));
    assert!(c.contains(&BinaryCapability::Download));
}

#[test]
fn ssh_has_multiple_capabilities() {
    let c = caps("ssh");
    assert!(c.contains(&BinaryCapability::Shell));
    assert!(c.contains(&BinaryCapability::Command));
    assert!(c.contains(&BinaryCapability::Upload));
    assert!(c.contains(&BinaryCapability::Download));
}

// ========================================================
// All entries have at least one capability
// ========================================================

#[test]
fn all_entries_have_capabilities() {
    for e in rules::gtfobins::GTFOBINS {
        assert!(
            !e.capabilities.is_empty(),
            "entry '{}' has no capabilities",
            e.name
        );
    }
}

// ========================================================
// All entries have non-empty names
// ========================================================

#[test]
fn all_entries_have_names() {
    for e in rules::gtfobins::GTFOBINS {
        assert!(!e.name.is_empty(), "found entry with empty name");
    }
}

// ========================================================
// Specific entry lookups (remaining to reach 30+)
// ========================================================

#[test]
fn nano_has_file_read_and_write() {
    assert!(has_cap("nano", BinaryCapability::FileRead));
    assert!(has_cap("nano", BinaryCapability::FileWrite));
}

#[test]
fn tar_has_command() {
    assert!(has_cap("tar", BinaryCapability::Command));
}

#[test]
fn sed_has_file_read_and_write() {
    assert!(has_cap("sed", BinaryCapability::FileRead));
    assert!(has_cap("sed", BinaryCapability::FileWrite));
}

#[test]
fn openssl_has_reverse_shell() {
    assert!(has_cap("openssl", BinaryCapability::ReverseShell));
}

#[test]
fn rsync_has_upload_download_command() {
    assert!(has_cap("rsync", BinaryCapability::Upload));
    assert!(has_cap("rsync", BinaryCapability::Download));
    assert!(has_cap("rsync", BinaryCapability::Command));
}

#[test]
fn perl_has_reverse_shell() {
    assert!(has_cap("perl", BinaryCapability::ReverseShell));
}

#[test]
fn ruby_has_reverse_shell() {
    assert!(has_cap("ruby", BinaryCapability::ReverseShell));
}

#[test]
fn php_has_reverse_shell() {
    assert!(has_cap("php", BinaryCapability::ReverseShell));
}

#[test]
fn node_has_reverse_shell() {
    assert!(has_cap("node", BinaryCapability::ReverseShell));
}

#[test]
fn ftp_has_shell_upload_download() {
    assert!(has_cap("ftp", BinaryCapability::Shell));
    assert!(has_cap("ftp", BinaryCapability::Upload));
    assert!(has_cap("ftp", BinaryCapability::Download));
}
