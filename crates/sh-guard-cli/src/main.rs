use std::io::{self, BufRead};
use std::process;

use clap::Parser;
use colored::Colorize;
use sh_guard_core::{classify, AnalysisResult, ClassifyContext, RiskLevel, Shell};

// ---------------------------------------------------------------------------
// CLI argument definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "sh-guard",
    about = "Semantic shell command safety classifier",
    version,
    long_about = "Analyzes shell commands for security risks using AST parsing, \
                  data-flow analysis, and context-aware risk scoring."
)]
struct Cli {
    /// Shell command to analyze
    command: Option<String>,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Read commands from stdin (one per line)
    #[arg(long)]
    stdin: bool,

    /// Current working directory for context
    #[arg(long)]
    cwd: Option<String>,

    /// Project root directory for context
    #[arg(long, alias = "project-root")]
    project_root: Option<String>,

    /// User home directory for context
    #[arg(long, alias = "home-dir")]
    home_dir: Option<String>,

    /// Protected paths (comma-separated)
    #[arg(long, alias = "protected-paths", value_delimiter = ',')]
    protected_paths: Vec<String>,

    /// Shell type (bash or zsh)
    #[arg(long, default_value = "bash")]
    shell: String,

    /// Path to custom rules TOML file
    #[arg(long)]
    rules: Option<String>,

    /// Suppress output, only set exit code
    #[arg(long, short)]
    quiet: bool,

    /// Use exit codes based on risk level (for hook integration)
    #[arg(long, alias = "exit-code")]
    exit_code: bool,
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

/// Map a RiskLevel to the process exit code.
fn exit_code_for_level(level: RiskLevel) -> i32 {
    match level {
        RiskLevel::Safe => 0,
        RiskLevel::Caution => 1,
        RiskLevel::Danger => 2,
        RiskLevel::Critical => 3,
    }
}

/// Render a human-readable, colored single-line (or multi-line for high risk) output.
fn format_human(result: &AnalysisResult) -> String {
    let label = match result.level {
        RiskLevel::Safe => "SAFE".green().to_string(),
        RiskLevel::Caution => "CAUTION".yellow().to_string(),
        RiskLevel::Danger => "DANGER".red().to_string(),
        RiskLevel::Critical => "CRITICAL".bright_red().bold().to_string(),
    };

    let mut output = format!("{} ({}): {}", label, result.score, result.reason);

    // For Danger and Critical, show additional details
    if result.level >= RiskLevel::Danger {
        // Pipeline taint flow description
        if let Some(ref pf) = result.pipeline_flow {
            for taint in &pf.taint_flows {
                output.push_str(&format!(
                    "\n  Pipeline: {} ({})",
                    taint.escalation_reason,
                    taint
                        .sink
                        .technique_label()
                        .unwrap_or_else(|| "data flow".to_string()),
                ));
            }
        }

        // Risk factors
        if !result.risk_factors.is_empty() {
            let factors: Vec<String> = result
                .risk_factors
                .iter()
                .map(|rf| format!("{:?}", rf).to_lowercase())
                .collect();
            output.push_str(&format!("\n  Risk factors: {}", factors.join(", ")));
        }

        // MITRE ATT&CK technique IDs
        if !result.mitre_mappings.is_empty() {
            let ids: Vec<String> = result
                .mitre_mappings
                .iter()
                .map(|m| format!("{} ({})", m.technique_id, m.technique_name))
                .collect();
            output.push_str(&format!("\n  MITRE ATT&CK: {}", ids.join(", ")));
        }
    }

    output
}

/// Helper trait to produce a short label for taint sinks.
trait TaintSinkLabel {
    fn technique_label(&self) -> Option<String>;
}

impl TaintSinkLabel for sh_guard_core::TaintSink {
    fn technique_label(&self) -> Option<String> {
        match self {
            sh_guard_core::TaintSink::NetworkSend => Some("T1041".to_string()),
            sh_guard_core::TaintSink::FileWrite { path } => {
                Some(format!("file write: {}", path))
            }
            sh_guard_core::TaintSink::Execution => Some("execution sink".to_string()),
            sh_guard_core::TaintSink::Display => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Build a ClassifyContext from CLI flags.
fn build_context(cli: &Cli) -> Option<ClassifyContext> {
    let shell = match cli.shell.to_lowercase().as_str() {
        "zsh" => Shell::Zsh,
        _ => Shell::Bash,
    };

    let has_context = cli.cwd.is_some()
        || cli.project_root.is_some()
        || cli.home_dir.is_some()
        || !cli.protected_paths.is_empty()
        || shell != Shell::Bash;

    if has_context {
        Some(ClassifyContext {
            cwd: cli.cwd.clone(),
            project_root: cli.project_root.clone(),
            home_dir: cli.home_dir.clone(),
            protected_paths: cli.protected_paths.clone(),
            shell,
        })
    } else {
        None
    }
}

/// Analyse a single command and produce output / collect exit code.
fn analyse_one(command: &str, context: Option<&ClassifyContext>, cli: &Cli) -> i32 {
    let result = classify(command, context);

    if !cli.quiet {
        if cli.json {
            // Full AnalysisResult as JSON
            let json = serde_json::to_string(&result).expect("serialization should not fail");
            println!("{}", json);
        } else {
            println!("{}", format_human(&result));
        }
    }

    exit_code_for_level(result.level)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // Validate: need either a positional command or --stdin
    if cli.command.is_none() && !cli.stdin {
        eprintln!("Error: provide a command to analyse or use --stdin");
        process::exit(1);
    }

    // Load user rules if specified (currently informational --
    // the core classify() uses built-in rules; custom RuleSet support
    // will be wired in a future release).
    if let Some(ref rules_path) = cli.rules {
        let path = std::path::Path::new(rules_path);
        if !path.exists() {
            eprintln!("Warning: rules file not found: {}", rules_path);
        }
        // RuleSet::with_user_rules is available but not yet threaded through
        // classify(). We load it here for validation / future use.
        let _ruleset = sh_guard_core::rules::RuleSet::with_user_rules(path);
    }

    let context = build_context(&cli);
    let ctx_ref = context.as_ref();

    if cli.stdin {
        // Batch mode: read one command per line from stdin.
        let stdin = io::stdin();
        let mut worst_exit = 0i32;

        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error reading stdin: {}", e);
                    process::exit(1);
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let code = analyse_one(trimmed, ctx_ref, &cli);
            if code > worst_exit {
                worst_exit = code;
            }
        }

        process::exit(worst_exit);
    }

    // Single command mode.
    if let Some(ref command) = cli.command {
        let code = analyse_one(command, ctx_ref, &cli);
        process::exit(code);
    }
}
