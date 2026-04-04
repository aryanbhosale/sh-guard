use sh_guard_core::test_internals::parser_fallback::parse_fallback;
use sh_guard_core::test_internals::*;

// ========================================================
// Simple command parsing
// ========================================================

#[test]
fn simple_echo_hello() {
    let parsed = parse_fallback("echo hello");
    assert_eq!(parsed.segments.len(), 1);
    assert_eq!(parsed.segments[0].executable.as_deref(), Some("echo"));
    assert_eq!(parsed.segments[0].args.len(), 1);
    assert_eq!(parsed.segments[0].args[0].value, "hello");
}

#[test]
fn simple_ls_la() {
    let parsed = parse_fallback("ls -la /tmp");
    assert_eq!(parsed.segments.len(), 1);
    let seg = &parsed.segments[0];
    assert_eq!(seg.executable.as_deref(), Some("ls"));
    assert_eq!(seg.args.len(), 2);
}

// ========================================================
// Pipeline splitting
// ========================================================

#[test]
fn pipeline_two_segments() {
    let parsed = parse_fallback("cat file | grep pattern");
    assert_eq!(parsed.segments.len(), 2);
    assert_eq!(parsed.segments[0].executable.as_deref(), Some("cat"));
    assert_eq!(parsed.segments[1].executable.as_deref(), Some("grep"));
    assert_eq!(parsed.chain_operators.len(), 1);
    assert_eq!(parsed.chain_operators[0], ChainOperator::Pipe);
}

#[test]
fn pipeline_three_segments() {
    let parsed = parse_fallback("cat file | sort | uniq");
    assert_eq!(parsed.segments.len(), 3);
    assert_eq!(parsed.chain_operators.len(), 2);
}

// ========================================================
// Operator splitting: &&, ||, ;
// ========================================================

#[test]
fn and_operator() {
    let parsed = parse_fallback("make && make install");
    assert_eq!(parsed.segments.len(), 2);
    assert_eq!(parsed.chain_operators[0], ChainOperator::And);
}

#[test]
fn or_operator() {
    let parsed = parse_fallback("test -f file || echo missing");
    assert_eq!(parsed.segments.len(), 2);
    assert_eq!(parsed.chain_operators[0], ChainOperator::Or);
}

#[test]
fn sequence_operator() {
    let parsed = parse_fallback("cd /tmp ; ls");
    assert_eq!(parsed.segments.len(), 2);
    assert_eq!(parsed.chain_operators[0], ChainOperator::Sequence);
}

#[test]
fn background_operator() {
    let parsed = parse_fallback("sleep 10 & echo done");
    assert!(parsed.chain_operators.contains(&ChainOperator::Background));
}

#[test]
fn mixed_operators_correct_order() {
    let parsed = parse_fallback("a | b && c || d ; e");
    assert_eq!(parsed.segments.len(), 5);
    assert_eq!(parsed.chain_operators[0], ChainOperator::Pipe);
    assert_eq!(parsed.chain_operators[1], ChainOperator::And);
    assert_eq!(parsed.chain_operators[2], ChainOperator::Or);
    assert_eq!(parsed.chain_operators[3], ChainOperator::Sequence);
}

// ========================================================
// Quoted operators not split
// ========================================================

#[test]
fn single_quoted_pipe_not_split() {
    let parsed = parse_fallback("echo 'a | b'");
    assert_eq!(parsed.segments.len(), 1);
    assert_eq!(parsed.chain_operators.len(), 0);
}

#[test]
fn double_quoted_pipe_not_split() {
    let parsed = parse_fallback("echo \"a | b\"");
    assert_eq!(parsed.segments.len(), 1);
    assert_eq!(parsed.chain_operators.len(), 0);
}

#[test]
fn single_quoted_and_not_split() {
    let parsed = parse_fallback("echo 'a && b'");
    assert_eq!(parsed.segments.len(), 1);
    assert_eq!(parsed.chain_operators.len(), 0);
}

#[test]
fn double_quoted_semicolon_not_split() {
    let parsed = parse_fallback("echo \"a ; b\"");
    assert_eq!(parsed.segments.len(), 1);
    assert_eq!(parsed.chain_operators.len(), 0);
}

// ========================================================
// Empty/whitespace input
// ========================================================

#[test]
fn empty_string_produces_one_segment() {
    let parsed = parse_fallback("");
    assert_eq!(parsed.segments.len(), 1);
    assert!(parsed.segments[0].executable.is_none());
}

#[test]
fn whitespace_only_produces_one_segment() {
    let parsed = parse_fallback("   \t  ");
    assert_eq!(parsed.segments.len(), 1);
    assert!(parsed.segments[0].executable.is_none());
}

// ========================================================
// Warning markers
// ========================================================

#[test]
fn fallback_warning_present() {
    let parsed = parse_fallback("anything");
    assert!(parsed
        .parse_warnings
        .iter()
        .any(|w| { matches!(w, ParseWarning::TreeSitterError(msg) if msg.contains("fallback")) }));
}

// ========================================================
// Expansion detection in args
// ========================================================

#[test]
fn variable_expansion_detected() {
    let parsed = parse_fallback("echo $HOME");
    let arg = &parsed.segments[0].args[0];
    assert!(arg.has_expansion);
    assert_eq!(arg.expansion_type, Some(ExpansionType::Variable));
}

#[test]
fn glob_expansion_detected() {
    let parsed = parse_fallback("ls *.rs");
    let arg = &parsed.segments[0].args[0];
    assert!(arg.has_expansion);
    assert_eq!(arg.expansion_type, Some(ExpansionType::Glob));
}

#[test]
fn backtick_expansion_detected() {
    let parsed = parse_fallback("echo `date`");
    let arg = &parsed.segments[0].args[0];
    assert!(arg.has_expansion);
    assert_eq!(arg.expansion_type, Some(ExpansionType::Command));
}

#[test]
fn no_expansion_for_plain_arg() {
    let parsed = parse_fallback("echo hello");
    let arg = &parsed.segments[0].args[0];
    assert!(!arg.has_expansion);
    assert_eq!(arg.expansion_type, None);
}

// ========================================================
// Subshell detection
// ========================================================

#[test]
fn subshell_detected() {
    let parsed = parse_fallback("(echo hello)");
    assert!(parsed.segments[0].is_subshell);
}

// ========================================================
// Complex commands
// ========================================================

#[test]
fn long_pipeline_10_segments() {
    let parsed = parse_fallback("a | b | c | d | e | f | g | h | i | j");
    assert_eq!(parsed.segments.len(), 10);
    assert_eq!(parsed.chain_operators.len(), 9);
}

#[test]
fn curl_with_many_flags() {
    let parsed = parse_fallback(
        "curl -X POST https://example.com -d @file.txt -H 'Content-Type: application/json'",
    );
    let seg = &parsed.segments[0];
    assert_eq!(seg.executable.as_deref(), Some("curl"));
    assert!(seg.args.len() >= 4);
}
