use sh_guard_core::test_internals::*;
use sh_guard_core::Shell;

// ========================================================
// Helper
// ========================================================

fn parse_bash(cmd: &str) -> ParsedCommand {
    parse(cmd, Shell::Bash)
}

// ========================================================
// 1. Simple commands
// ========================================================

#[test]
fn simple_ls_la_tmp() {
    let p = parse_bash("ls -la /tmp");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    assert_eq!(seg.executable.as_deref(), Some("ls"));
    let arg_values: Vec<&str> = seg.args.iter().map(|a| a.value.as_str()).collect();
    assert!(arg_values.contains(&"-la"), "expected -la in args: {:?}", arg_values);
    assert!(arg_values.contains(&"/tmp"), "expected /tmp in args: {:?}", arg_values);
}

#[test]
fn simple_absolute_path_executable() {
    let p = parse_bash("/usr/bin/ls");
    assert_eq!(p.segments.len(), 1);
    assert_eq!(p.segments[0].executable.as_deref(), Some("/usr/bin/ls"));
}

#[test]
fn simple_echo_hello_world() {
    let p = parse_bash("echo hello world");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    assert_eq!(seg.executable.as_deref(), Some("echo"));
    let arg_values: Vec<&str> = seg.args.iter().map(|a| a.value.as_str()).collect();
    assert!(arg_values.contains(&"hello"), "expected hello in args: {:?}", arg_values);
    assert!(arg_values.contains(&"world"), "expected world in args: {:?}", arg_values);
}

#[test]
fn simple_empty_string() {
    let p = parse_bash("");
    // Should produce at least a default segment or empty segments
    // Either way, no executable
    if !p.segments.is_empty() {
        assert!(p.segments[0].executable.is_none());
    }
}

#[test]
fn simple_whitespace_only() {
    let p = parse_bash("   ");
    if !p.segments.is_empty() {
        assert!(p.segments[0].executable.is_none());
    }
}

#[test]
fn simple_command_with_equals_arg() {
    let p = parse_bash("grep --color=auto foo");
    assert_eq!(p.segments.len(), 1);
    assert_eq!(p.segments[0].executable.as_deref(), Some("grep"));
}

// ========================================================
// 2. Pipelines
// ========================================================

#[test]
fn pipeline_cat_grep() {
    let p = parse_bash("cat file | grep error");
    assert_eq!(p.segments.len(), 2, "segments: {:?}", p.segments);
    assert_eq!(p.chain_operators.len(), 1);
    assert_eq!(p.chain_operators[0], ChainOperator::Pipe);
    assert_eq!(p.segments[0].executable.as_deref(), Some("cat"));
    assert_eq!(p.segments[1].executable.as_deref(), Some("grep"));
}

#[test]
fn pipeline_three_stages() {
    let p = parse_bash("a | b | c");
    assert_eq!(p.segments.len(), 3);
    assert_eq!(p.chain_operators.len(), 2);
    assert!(p.chain_operators.iter().all(|op| *op == ChainOperator::Pipe));
}

#[test]
fn pipeline_ten_stages() {
    let p = parse_bash("a | b | c | d | e | f | g | h | i | j");
    assert_eq!(p.segments.len(), 10, "segments: {:?}", p.segments);
    assert_eq!(p.chain_operators.len(), 9);
    assert!(p.chain_operators.iter().all(|op| *op == ChainOperator::Pipe));
}

#[test]
fn pipeline_with_args() {
    let p = parse_bash("ps aux | grep python | wc -l");
    assert_eq!(p.segments.len(), 3);
    assert_eq!(p.chain_operators.len(), 2);
    assert_eq!(p.segments[0].executable.as_deref(), Some("ps"));
    assert_eq!(p.segments[1].executable.as_deref(), Some("grep"));
    assert_eq!(p.segments[2].executable.as_deref(), Some("wc"));
}

#[test]
fn pipeline_preserves_segment_order() {
    let p = parse_bash("cat /etc/passwd | sort | uniq -c | head -5");
    assert_eq!(p.segments.len(), 4);
    assert_eq!(p.segments[0].executable.as_deref(), Some("cat"));
    assert_eq!(p.segments[1].executable.as_deref(), Some("sort"));
    assert_eq!(p.segments[2].executable.as_deref(), Some("uniq"));
    assert_eq!(p.segments[3].executable.as_deref(), Some("head"));
}

// ========================================================
// 3. Compound commands (&&, ||, ;)
// ========================================================

#[test]
fn compound_and() {
    let p = parse_bash("mkdir dir && cd dir");
    assert_eq!(p.segments.len(), 2, "segments: {:?}", p.segments);
    assert_eq!(p.chain_operators.len(), 1);
    assert_eq!(p.chain_operators[0], ChainOperator::And);
}

#[test]
fn compound_or() {
    let p = parse_bash("test -f file || echo missing");
    assert_eq!(p.segments.len(), 2, "segments: {:?}", p.segments);
    assert_eq!(p.chain_operators.len(), 1);
    assert_eq!(p.chain_operators[0], ChainOperator::Or);
}

#[test]
fn compound_sequence() {
    let p = parse_bash("echo a ; echo b");
    assert_eq!(p.segments.len(), 2, "segments: {:?}", p.segments);
    assert_eq!(p.chain_operators.len(), 1);
    assert_eq!(p.chain_operators[0], ChainOperator::Sequence);
}

#[test]
fn compound_mixed() {
    let p = parse_bash("a | b && c ; d");
    // This should produce segments for a, b, c, d
    assert!(p.segments.len() >= 3, "expected at least 3 segments, got {}: {:?}", p.segments.len(), p.segments);
    // Should have mixed operators including at least Pipe and And
    let ops: Vec<&ChainOperator> = p.chain_operators.iter().collect();
    assert!(ops.contains(&&ChainOperator::Pipe), "expected Pipe in {:?}", ops);
    assert!(ops.contains(&&ChainOperator::And), "expected And in {:?}", ops);
}

#[test]
fn compound_background() {
    let p = parse_bash("sleep 10 &");
    // Background operator should be detected
    // The command might parse as 1 segment with a background operator, or
    // the segment count depends on implementation
    assert!(!p.segments.is_empty());
    assert_eq!(p.segments[0].executable.as_deref(), Some("sleep"));
}

// ========================================================
// 4. Redirections
// ========================================================

#[test]
fn redirect_out() {
    let p = parse_bash("echo hello > out.txt");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    assert_eq!(seg.executable.as_deref(), Some("echo"));
    assert!(!seg.redirections.is_empty(), "expected redirections, got none");
    let redir = &seg.redirections[0];
    assert_eq!(redir.direction, RedirDirection::Out);
    assert_eq!(redir.target, "out.txt");
}

#[test]
fn redirect_in() {
    let p = parse_bash("sort < input.txt");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    assert!(!seg.redirections.is_empty(), "expected redirections");
    let redir = &seg.redirections[0];
    assert_eq!(redir.direction, RedirDirection::In);
    assert_eq!(redir.target, "input.txt");
}

#[test]
fn redirect_append() {
    let p = parse_bash("echo hello >> log.txt");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    assert!(!seg.redirections.is_empty(), "expected redirections");
    let redir = &seg.redirections[0];
    assert_eq!(redir.direction, RedirDirection::Append);
    assert_eq!(redir.target, "log.txt");
}

#[test]
fn redirect_with_fd() {
    let p = parse_bash("command 2> error.log");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    assert!(!seg.redirections.is_empty(), "expected redirections");
    let redir = &seg.redirections[0];
    assert_eq!(redir.fd, Some(2));
    assert_eq!(redir.direction, RedirDirection::Out);
    assert_eq!(redir.target, "error.log");
}

// ========================================================
// 5. Quote types
// ========================================================

#[test]
fn quote_single() {
    let p = parse_bash("echo 'hello'");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    let quoted_args: Vec<&Argument> = seg.args.iter().filter(|a| a.is_quoted).collect();
    assert!(!quoted_args.is_empty(), "expected a quoted arg, args: {:?}", seg.args);
    assert_eq!(quoted_args[0].quote_type, Some(QuoteType::Single));
}

#[test]
fn quote_double() {
    let p = parse_bash("echo \"hello\"");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    let quoted_args: Vec<&Argument> = seg.args.iter().filter(|a| a.is_quoted).collect();
    assert!(!quoted_args.is_empty(), "expected a quoted arg, args: {:?}", seg.args);
    assert_eq!(quoted_args[0].quote_type, Some(QuoteType::Double));
}

#[test]
fn quote_ansi_c() {
    let p = parse_bash("echo $'hello\\n'");
    // Should trigger AnsiCQuoting warning
    let has_ansi_warning = p.parse_warnings.iter().any(|w| matches!(w, ParseWarning::AnsiCQuoting));
    assert!(has_ansi_warning, "expected AnsiCQuoting warning, got: {:?}", p.parse_warnings);
}

// ========================================================
// 6. Expansion detection
// ========================================================

#[test]
fn expansion_variable() {
    let p = parse_bash("echo $HOME");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    let expanded_args: Vec<&Argument> = seg.args.iter().filter(|a| a.has_expansion).collect();
    assert!(!expanded_args.is_empty(), "expected expansion, args: {:?}", seg.args);
    assert_eq!(expanded_args[0].expansion_type, Some(ExpansionType::Variable));
}

#[test]
fn expansion_command_substitution() {
    let p = parse_bash("echo $(date)");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    let expanded_args: Vec<&Argument> = seg.args.iter().filter(|a| a.has_expansion).collect();
    assert!(!expanded_args.is_empty(), "expected expansion, args: {:?}", seg.args);
    assert_eq!(expanded_args[0].expansion_type, Some(ExpansionType::Command));
}

#[test]
fn expansion_glob() {
    let p = parse_bash("ls *.txt");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    let expanded_args: Vec<&Argument> = seg.args.iter().filter(|a| a.has_expansion).collect();
    assert!(!expanded_args.is_empty(), "expected glob expansion, args: {:?}", seg.args);
    assert_eq!(expanded_args[0].expansion_type, Some(ExpansionType::Glob));
}

#[test]
fn expansion_tilde() {
    let p = parse_bash("cd ~/projects");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    let expanded_args: Vec<&Argument> = seg.args.iter().filter(|a| a.has_expansion).collect();
    assert!(!expanded_args.is_empty(), "expected tilde expansion, args: {:?}", seg.args);
    assert_eq!(expanded_args[0].expansion_type, Some(ExpansionType::Tilde));
}

#[test]
fn expansion_backtick_command() {
    let p = parse_bash("echo `date`");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    let expanded_args: Vec<&Argument> = seg.args.iter().filter(|a| a.has_expansion).collect();
    assert!(!expanded_args.is_empty(), "expected command expansion, args: {:?}", seg.args);
    assert_eq!(expanded_args[0].expansion_type, Some(ExpansionType::Command));
}

// ========================================================
// 7. Parse warnings
// ========================================================

#[test]
fn warning_control_characters() {
    let cmd = "echo \x01hello";
    let p = parse_bash(cmd);
    let has_warning = p.parse_warnings.iter().any(|w| matches!(w, ParseWarning::ControlCharacters(_)));
    assert!(has_warning, "expected ControlCharacters warning, got: {:?}", p.parse_warnings);
}

#[test]
fn warning_unicode_whitespace() {
    // \u{00A0} is non-breaking space
    let cmd = "echo\u{00A0}hello";
    let p = parse_bash(cmd);
    let has_warning = p.parse_warnings.iter().any(|w| matches!(w, ParseWarning::UnicodeWhitespace(_)));
    assert!(has_warning, "expected UnicodeWhitespace warning, got: {:?}", p.parse_warnings);
}

#[test]
fn warning_carriage_return() {
    let cmd = "echo hello\r";
    let p = parse_bash(cmd);
    let has_warning = p.parse_warnings.iter().any(|w| matches!(w, ParseWarning::CarriageReturn));
    assert!(has_warning, "expected CarriageReturn warning, got: {:?}", p.parse_warnings);
}

#[test]
fn warning_ansi_c_quoting() {
    let cmd = "echo $'\\x41'";
    let p = parse_bash(cmd);
    let has_warning = p.parse_warnings.iter().any(|w| matches!(w, ParseWarning::AnsiCQuoting));
    assert!(has_warning, "expected AnsiCQuoting warning, got: {:?}", p.parse_warnings);
}

#[test]
fn warning_escaped_operators() {
    let cmd = "echo hello \\; rm -rf /";
    let p = parse_bash(cmd);
    let has_warning = p.parse_warnings.iter().any(|w| matches!(w, ParseWarning::EscapedOperators));
    assert!(has_warning, "expected EscapedOperators warning, got: {:?}", p.parse_warnings);
}

#[test]
fn warning_multiple_issues() {
    let cmd = "echo\u{00A0}\x01hello\r";
    let p = parse_bash(cmd);
    assert!(p.parse_warnings.len() >= 2, "expected multiple warnings, got: {:?}", p.parse_warnings);
}

// ========================================================
// 8. Variable assignments
// ========================================================

#[test]
fn variable_assignment_before_command() {
    let p = parse_bash("FOO=bar echo test");
    assert_eq!(p.segments.len(), 1);
    let seg = &p.segments[0];
    assert_eq!(seg.executable.as_deref(), Some("echo"));
    assert!(!seg.assignments.is_empty(), "expected assignments, got: {:?}", seg.assignments);
    assert_eq!(seg.assignments[0].name, "FOO");
    assert_eq!(seg.assignments[0].value, "bar");
}

// ========================================================
// 9. Subshell detection
// ========================================================

#[test]
fn subshell_detection() {
    let p = parse_bash("(cd /tmp && ls)");
    // Should detect subshell
    let has_subshell = p.segments.iter().any(|s| s.is_subshell);
    assert!(has_subshell, "expected subshell, segments: {:?}", p.segments);
}
