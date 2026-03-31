use crate::rules::paths;
use crate::types::*;

/// Resolve the scope of a target path given a context.
pub fn resolve_scope(path: &str, context: Option<&ClassifyContext>) -> TargetScope {
    let path = normalize_path(path);

    // Check for root
    if path == "/" {
        return TargetScope::Root;
    }

    // Check for home directory
    if let Some(ctx) = context {
        if let Some(home) = &ctx.home_dir {
            let home_normalized = normalize_path(home);
            if path == home_normalized || path == format!("{}/", home_normalized) {
                return TargetScope::Home;
            }
        }
    }

    // Check for tilde (without context, assume home)
    if path == "~" || path == "~/" {
        return TargetScope::Home;
    }

    // Check for system directories
    let system_prefixes = [
        "/etc", "/usr", "/bin", "/sbin", "/lib", "/var", "/opt", "/proc", "/sys", "/boot",
    ];
    if system_prefixes.iter().any(|p| path.starts_with(p)) {
        return TargetScope::System;
    }

    // Default to SingleFile (caller upgrades to Directory/DirectoryRecursive based on flags)
    TargetScope::SingleFile
}

/// Determine the sensitivity of a target path.
pub fn resolve_sensitivity(path: &str, context: Option<&ClassifyContext>) -> Sensitivity {
    // Check user-defined protected paths first
    if let Some(ctx) = context {
        for protected in &ctx.protected_paths {
            if path.contains(protected) || path.ends_with(protected) {
                return Sensitivity::Protected;
            }
        }
    }

    // Check built-in path rules
    if let Some((sensitivity, _desc)) = paths::match_sensitivity(path) {
        return sensitivity;
    }

    Sensitivity::Normal
}

/// Apply context-based score adjustment.
pub fn context_adjustment(path: &str, intent: &Intent, context: Option<&ClassifyContext>) -> i16 {
    let Some(ctx) = context else {
        return 5; // No context = conservative default
    };

    let path = resolve_relative_path(path, ctx);
    let mut adjustment: i16 = 0;

    // Inside project root? Reduce risk for writes/deletes
    if let Some(project_root) = &ctx.project_root {
        let root = normalize_path(project_root);
        if path.starts_with(&root) {
            match intent {
                Intent::Write | Intent::Delete => adjustment -= 10,
                _ => {}
            }

            // Inside common build/temp directories? Further reduce
            let relative = path[root.len()..].trim_start_matches('/');
            let build_dirs = [
                "build",
                "dist",
                "target",
                "out",
                "tmp",
                ".cache",
                "node_modules",
                "__pycache__",
                ".next",
                ".nuxt",
            ];
            if build_dirs.iter().any(|d| relative.starts_with(d)) {
                adjustment -= 15;
            }
        } else {
            // Escapes project boundary
            if matches!(intent, Intent::Write | Intent::Delete) {
                adjustment += 20;
            }
        }
    }

    // Targets home dir from outside CWD?
    if let Some(home) = &ctx.home_dir {
        let home_normalized = normalize_path(home);
        if path.starts_with(&home_normalized) {
            if let Some(cwd) = &ctx.cwd {
                if !cwd.starts_with(&home_normalized) || path == home_normalized {
                    adjustment += 15;
                }
            }
        }
    }

    // Targets a protected path?
    for protected in &ctx.protected_paths {
        if path.contains(protected) {
            adjustment += 25;
            break;
        }
    }

    adjustment
}

/// Resolve a relative path against the context's CWD (or project_root).
/// Absolute paths and tilde paths are left as-is after normalization.
fn resolve_relative_path(path: &str, ctx: &ClassifyContext) -> String {
    let normalized = normalize_path(path);

    // Already absolute or tilde-based
    if normalized.starts_with('/') || normalized.starts_with('~') {
        return normalized;
    }

    // Relative path -- resolve against CWD (fallback to project_root)
    let base = ctx
        .cwd
        .as_deref()
        .or(ctx.project_root.as_deref())
        .unwrap_or("");

    if base.is_empty() {
        return normalized;
    }

    let base = normalize_path(base);
    let relative = normalized.trim_start_matches("./");
    normalize_path(&format!("{}/{}", base, relative))
}

/// Normalize a path: remove trailing slashes, collapse //.
pub fn normalize_path(path: &str) -> String {
    let mut p = path.to_string();

    // Don't try to resolve ~ to actual home dir here -- that requires env access.
    // Just normalize the string representation.

    // Remove trailing slash (unless it's just "/")
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }

    // Collapse double slashes
    while p.contains("//") {
        p = p.replace("//", "/");
    }

    p
}
