use sh_guard_core::*;
use std::fs;

fn parse_corpus_line(line: &str) -> Option<(String, String, u8, u8)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Split from the right: "command | expected_level | min-max"
    let parts: Vec<&str> = line.rsplitn(3, '|').collect();
    if parts.len() != 3 {
        return None;
    }

    let score_range = parts[0].trim();
    let expected_level = parts[1].trim().to_string();
    let command = parts[2].trim().to_string();

    let range_parts: Vec<&str> = score_range.split('-').collect();
    if range_parts.len() != 2 {
        return None;
    }

    let min: u8 = range_parts[0].trim().parse().ok()?;
    let max: u8 = range_parts[1].trim().parse().ok()?;

    Some((command, expected_level, min, max))
}

fn run_corpus(filename: &str, shell: Shell) {
    let path = format!(
        "{}/../../../../tests/corpus/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );

    // Also try the direct path relative to workspace root
    let path = if std::path::Path::new(&path).exists() {
        path
    } else {
        let alt = format!(
            "{}/../../tests/corpus/{}",
            env!("CARGO_MANIFEST_DIR"),
            filename
        );
        if std::path::Path::new(&alt).exists() {
            alt
        } else {
            // Try workspace root
            let workspace = format!(
                "{}/tests/corpus/{}",
                env!("CARGO_MANIFEST_DIR").replace("/crates/sh-guard-core", ""),
                filename
            );
            workspace
        }
    };

    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));

    let ctx = if shell == Shell::Zsh {
        Some(ClassifyContext {
            cwd: None,
            project_root: None,
            home_dir: None,
            protected_paths: vec![],
            shell: Shell::Zsh,
        })
    } else {
        None
    };

    let mut tested = 0;
    let mut failures = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        if let Some((command, expected_level, min_score, max_score)) = parse_corpus_line(line) {
            let result = classify(&command, ctx.as_ref());

            let level_str = format!("{:?}", result.level).to_lowercase();

            if result.score < min_score || result.score > max_score {
                failures.push(format!(
                    "  {}:{}: '{}' scored {} (expected {}-{}), level={:?}",
                    filename,
                    line_num + 1,
                    command,
                    result.score,
                    min_score,
                    max_score,
                    result.level
                ));
            } else if level_str != expected_level {
                failures.push(format!(
                    "  {}:{}: '{}' level {:?} (expected {}), score={}",
                    filename,
                    line_num + 1,
                    command,
                    result.level,
                    expected_level,
                    result.score
                ));
            }

            tested += 1;
        }
    }

    if !failures.is_empty() {
        panic!(
            "{}: {} failures out of {} tests:\n{}",
            filename,
            failures.len(),
            tested,
            failures.join("\n")
        );
    }

    assert!(tested > 0, "No test cases found in {}", filename);
    eprintln!("{}: {} commands tested", filename, tested);
}

#[test]
fn corpus_safe() {
    run_corpus("safe.txt", Shell::Bash);
}

#[test]
fn corpus_caution() {
    run_corpus("caution.txt", Shell::Bash);
}

#[test]
fn corpus_danger() {
    run_corpus("danger.txt", Shell::Bash);
}

#[test]
fn corpus_critical() {
    run_corpus("critical.txt", Shell::Bash);
}

#[test]
fn corpus_pipelines() {
    run_corpus("pipelines.txt", Shell::Bash);
}

#[test]
fn corpus_injection() {
    run_corpus("injection.txt", Shell::Bash);
}

#[test]
fn corpus_evasion() {
    run_corpus("evasion.txt", Shell::Bash);
}

#[test]
fn corpus_zsh() {
    run_corpus("zsh.txt", Shell::Zsh);
}

#[test]
fn corpus_gtfobins() {
    run_corpus("gtfobins.txt", Shell::Bash);
}
