use crate::types::Sensitivity;

#[derive(Debug, Clone)]
pub struct PathRule {
    pub pattern: &'static str,
    pub sensitivity: Sensitivity,
    pub description: &'static str,
}

pub static SENSITIVE_PATHS: &[PathRule] = &[
    // --- Secrets ---
    PathRule {
        pattern: ".env",
        sensitivity: Sensitivity::Secrets,
        description: "Environment secrets",
    },
    PathRule {
        pattern: ".env.*",
        sensitivity: Sensitivity::Secrets,
        description: "Environment secrets variant",
    },
    PathRule {
        pattern: ".ssh",
        sensitivity: Sensitivity::Secrets,
        description: "SSH directory",
    },
    PathRule {
        pattern: ".ssh/*",
        sensitivity: Sensitivity::Secrets,
        description: "SSH keys and config",
    },
    PathRule {
        pattern: ".aws/credentials",
        sensitivity: Sensitivity::Secrets,
        description: "AWS credentials",
    },
    PathRule {
        pattern: ".aws/config",
        sensitivity: Sensitivity::Config,
        description: "AWS config",
    },
    PathRule {
        pattern: ".gnupg/*",
        sensitivity: Sensitivity::Secrets,
        description: "GPG keys",
    },
    PathRule {
        pattern: "credentials.json",
        sensitivity: Sensitivity::Secrets,
        description: "Service credentials",
    },
    PathRule {
        pattern: "*.pem",
        sensitivity: Sensitivity::Secrets,
        description: "TLS/SSH private key",
    },
    PathRule {
        pattern: "*.key",
        sensitivity: Sensitivity::Secrets,
        description: "Private key file",
    },
    PathRule {
        pattern: "*.p12",
        sensitivity: Sensitivity::Secrets,
        description: "PKCS12 certificate store",
    },
    PathRule {
        pattern: "*.pfx",
        sensitivity: Sensitivity::Secrets,
        description: "PKCS12 certificate",
    },
    PathRule {
        pattern: ".netrc",
        sensitivity: Sensitivity::Secrets,
        description: "FTP/HTTP credentials",
    },
    PathRule {
        pattern: ".npmrc",
        sensitivity: Sensitivity::Secrets,
        description: "npm auth tokens",
    },
    PathRule {
        pattern: ".pypirc",
        sensitivity: Sensitivity::Secrets,
        description: "PyPI credentials",
    },
    PathRule {
        pattern: ".docker/config.json",
        sensitivity: Sensitivity::Secrets,
        description: "Docker registry credentials",
    },
    PathRule {
        pattern: ".kube/config",
        sensitivity: Sensitivity::Secrets,
        description: "Kubernetes credentials",
    },
    PathRule {
        pattern: ".gcloud/*",
        sensitivity: Sensitivity::Secrets,
        description: "GCloud credentials",
    },
    PathRule {
        pattern: "id_rsa",
        sensitivity: Sensitivity::Secrets,
        description: "RSA private key",
    },
    PathRule {
        pattern: "id_ed25519",
        sensitivity: Sensitivity::Secrets,
        description: "Ed25519 private key",
    },
    PathRule {
        pattern: "id_ecdsa",
        sensitivity: Sensitivity::Secrets,
        description: "ECDSA private key",
    },
    PathRule {
        pattern: "*.secret",
        sensitivity: Sensitivity::Secrets,
        description: "Secret file",
    },
    PathRule {
        pattern: "*.secrets",
        sensitivity: Sensitivity::Secrets,
        description: "Secrets file",
    },
    PathRule {
        pattern: ".htpasswd",
        sensitivity: Sensitivity::Secrets,
        description: "HTTP Basic auth passwords",
    },
    PathRule {
        pattern: "token.json",
        sensitivity: Sensitivity::Secrets,
        description: "OAuth token",
    },
    // --- System ---
    PathRule {
        pattern: "/etc/passwd",
        sensitivity: Sensitivity::System,
        description: "User accounts",
    },
    PathRule {
        pattern: "/etc/shadow",
        sensitivity: Sensitivity::System,
        description: "Password hashes",
    },
    PathRule {
        pattern: "/etc/sudoers",
        sensitivity: Sensitivity::System,
        description: "Sudo configuration",
    },
    PathRule {
        pattern: "/etc/hosts",
        sensitivity: Sensitivity::System,
        description: "Host resolution",
    },
    PathRule {
        pattern: "/etc/resolv.conf",
        sensitivity: Sensitivity::System,
        description: "DNS configuration",
    },
    PathRule {
        pattern: "/etc/crontab",
        sensitivity: Sensitivity::System,
        description: "System cron jobs",
    },
    PathRule {
        pattern: "/etc/ssh/*",
        sensitivity: Sensitivity::System,
        description: "SSH server config",
    },
    PathRule {
        pattern: "/proc/*/environ",
        sensitivity: Sensitivity::System,
        description: "Process environment",
    },
    PathRule {
        pattern: "/proc/self/environ",
        sensitivity: Sensitivity::System,
        description: "Current process environment",
    },
    // --- Config ---
    PathRule {
        pattern: ".gitconfig",
        sensitivity: Sensitivity::Config,
        description: "Git config",
    },
    PathRule {
        pattern: ".git/config",
        sensitivity: Sensitivity::Config,
        description: "Repo git config",
    },
    PathRule {
        pattern: ".bashrc",
        sensitivity: Sensitivity::Config,
        description: "Bash startup",
    },
    PathRule {
        pattern: ".bash_profile",
        sensitivity: Sensitivity::Config,
        description: "Bash login",
    },
    PathRule {
        pattern: ".zshrc",
        sensitivity: Sensitivity::Config,
        description: "Zsh startup",
    },
    PathRule {
        pattern: ".zprofile",
        sensitivity: Sensitivity::Config,
        description: "Zsh login",
    },
    PathRule {
        pattern: ".profile",
        sensitivity: Sensitivity::Config,
        description: "Shell profile",
    },
    PathRule {
        pattern: ".vimrc",
        sensitivity: Sensitivity::Config,
        description: "Vim config",
    },
    PathRule {
        pattern: ".claude/*",
        sensitivity: Sensitivity::Config,
        description: "Claude Code config",
    },
    PathRule {
        pattern: ".cursor/*",
        sensitivity: Sensitivity::Config,
        description: "Cursor config",
    },
    PathRule {
        pattern: ".vscode/*",
        sensitivity: Sensitivity::Config,
        description: "VS Code config",
    },
    PathRule {
        pattern: ".config/*",
        sensitivity: Sensitivity::Config,
        description: "XDG config",
    },
    PathRule {
        pattern: "Makefile",
        sensitivity: Sensitivity::Config,
        description: "Build configuration",
    },
    PathRule {
        pattern: "Dockerfile",
        sensitivity: Sensitivity::Config,
        description: "Container build",
    },
    PathRule {
        pattern: "docker-compose.yml",
        sensitivity: Sensitivity::Config,
        description: "Container orchestration",
    },
    PathRule {
        pattern: ".terraform/*",
        sensitivity: Sensitivity::Secrets,
        description: "Terraform state (may contain secrets)",
    },
    PathRule {
        pattern: "terraform.tfstate",
        sensitivity: Sensitivity::Secrets,
        description: "Terraform state file",
    },
];

/// Check if a path matches any sensitive path rule.
/// Returns the highest sensitivity match, or None.
pub fn match_sensitivity(path: &str) -> Option<(Sensitivity, &'static str)> {
    let normalized = path.trim_start_matches("./");
    let basename = normalized.rsplit('/').next().unwrap_or(normalized);

    let mut best: Option<(Sensitivity, &'static str)> = None;

    for rule in SENSITIVE_PATHS {
        let matched = if rule.pattern.starts_with('/') {
            // Absolute path pattern — match full path against full pattern
            path_matches(normalized, rule.pattern)
        } else if rule.pattern.contains('/') {
            // Relative path with directory component
            normalized.ends_with(rule.pattern) || path_matches(normalized, rule.pattern)
        } else {
            // Basename pattern (may have wildcards)
            path_matches(basename, rule.pattern)
        };

        if matched {
            let dominated = best
                .as_ref()
                .map_or(true, |(s, _)| (rule.sensitivity.modifier()) > s.modifier());
            if dominated {
                best = Some((rule.sensitivity, rule.description));
            }
        }
    }

    best
}

/// Simple glob-style matching: supports * (any chars) and ? (single char).
fn path_matches(text: &str, pattern: &str) -> bool {
    if !pattern.contains('*') && !pattern.contains('?') {
        return text == pattern || text.ends_with(&format!("/{}", pattern));
    }

    // Convert glob to a simple match
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        // Only ? wildcards
        if text.len() != pattern.len() {
            return false;
        }
        return text
            .chars()
            .zip(pattern.chars())
            .all(|(t, p)| p == '?' || t == p);
    }

    // Handle * wildcards
    let mut remaining = text;

    // First part must match the start (if non-empty)
    if !parts[0].is_empty() {
        if !remaining.starts_with(parts[0]) {
            return false;
        }
        remaining = &remaining[parts[0].len()..];
    }

    // Last part must match the end
    let last = parts[parts.len() - 1];
    if !last.is_empty() {
        if !remaining.ends_with(last) {
            return false;
        }
        remaining = &remaining[..remaining.len() - last.len()];
    }

    // Middle parts must appear in order
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        match remaining.find(part) {
            Some(pos) => remaining = &remaining[pos + part.len()..],
            None => return false,
        }
    }

    true
}
