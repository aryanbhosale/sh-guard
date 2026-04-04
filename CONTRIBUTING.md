# Contributing to sh-guard

Thanks for your interest in contributing! Here's everything you need to get started.

## Development setup

1. Install [Rust](https://rustup.rs/) (1.80+)
2. Clone the repo:
   ```bash
   git clone https://github.com/aryanbhosale/sh-guard.git
   cd sh-guard
   ```
3. Run the tests:
   ```bash
   cargo test --workspace
   ```

## Making changes

1. Fork the repository
2. Create a branch from `main`:
   ```bash
   git checkout -b my-change
   ```
3. Make your changes
4. Ensure everything passes:
   ```bash
   cargo test --workspace
   cargo clippy --workspace -- -D warnings
   cargo fmt --all -- --check
   ```
5. Push and open a pull request against `main`

## What to work on

- Issues labeled [`good first issue`](https://github.com/aryanbhosale/sh-guard/labels/good%20first%20issue) are a great starting point
- Issues labeled [`help wanted`](https://github.com/aryanbhosale/sh-guard/labels/help%20wanted) are open for contribution
- Bug reports and feature requests are always welcome

## Architecture overview

Commands are parsed into an AST, then analyzed through a three-layer pipeline:

```
Shell command → tree-sitter AST → Semantic Analysis → Pipeline Taint → Risk Score
```

### Key files

```
crates/sh-guard-core/src/
  lib.rs              — Public API: classify() and classify_batch()
  parser.rs           — tree-sitter-bash AST parsing, extracts commands/args/flags/pipes
  parser_fallback.rs  — Regex fallback when tree-sitter fails
  analyzer.rs         — Maps parsed commands to intents, targets, and risk factors
  context.rs          — Path scope/sensitivity resolution
  scorer.rs           — Three-layer scoring engine with context adjustments
  pipeline.rs         — Pipeline taint analysis with data-flow tracking
  rules/
    commands.rs       — 157 command rule definitions
    paths.rs          — 51 path sensitivity rules
    injection.rs      — 25 injection detection patterns
    zsh.rs            — 15 zsh-specific rules
    gtfobins.rs       — 61 GTFOBins capability entries
    network.rs        — Taint flow matching rules
    mod.rs            — RuleSet with TOML user rule loading
  types.rs            — Core types: RiskLevel, AnalysisResult, CommandIntent, etc.
```

## Adding a new command rule

1. Add the rule to `crates/sh-guard-core/src/rules/commands.rs`
2. Add test cases to `crates/sh-guard-core/tests/test_rules_commands.rs`
3. Run `cargo test` to verify

## Adding a new injection pattern

1. Add the pattern to `crates/sh-guard-core/src/rules/injection.rs`
2. Add test cases to `crates/sh-guard-core/tests/test_rules_injection.rs`
3. Run `cargo test` to verify

## Adding a new taint flow rule

1. Add the rule to `crates/sh-guard-core/src/rules/network.rs`
2. Add test cases to `crates/sh-guard-core/tests/test_pipeline.rs`
3. Run `cargo test` to verify

## Code style

- Run `cargo fmt` before committing
- No clippy warnings (`cargo clippy --workspace -- -D warnings`)
- Write tests for new functionality
- Keep error messages concise and actionable

## Pull request process

1. PRs require review approval before merging
2. CI must pass (tests, clippy, fmt)
3. Keep PRs focused — one feature or fix per PR
4. Update the README if adding user-facing features
