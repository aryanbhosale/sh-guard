use crate::parser::*;

/// Fallback parser using simple splitting when tree-sitter fails.
pub fn parse_fallback(command: &str) -> ParsedCommand {
    let mut segments = vec![];
    let mut operators = vec![];

    // Split on unquoted operators (very basic -- doesn't handle all quoting edge cases)
    let parts = split_on_operators(command);

    for (text, op) in parts {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            if let Some(op) = op {
                operators.push(op);
            }
            continue;
        }

        if let Some(op) = op {
            operators.push(op);
        }

        // Extract executable as the first word
        let mut words = trimmed.split_whitespace();
        let executable = words.next().map(String::from);
        let args: Vec<Argument> = words
            .map(|w| Argument {
                value: w.to_string(),
                is_quoted: w.starts_with('\'') || w.starts_with('"'),
                quote_type: if w.starts_with('\'') {
                    Some(QuoteType::Single)
                } else if w.starts_with('"') {
                    Some(QuoteType::Double)
                } else {
                    None
                },
                has_expansion: w.contains('$') || w.contains('`') || w.contains('*'),
                expansion_type: if w.contains('$') {
                    Some(ExpansionType::Variable)
                } else if w.contains('`') {
                    Some(ExpansionType::Command)
                } else if w.contains('*') || w.contains('?') {
                    Some(ExpansionType::Glob)
                } else {
                    None
                },
            })
            .collect();

        segments.push(CommandSegment {
            raw: trimmed.to_string(),
            executable,
            args,
            redirections: vec![],
            assignments: vec![],
            is_subshell: trimmed.starts_with('('),
        });
    }

    if segments.is_empty() {
        segments.push(CommandSegment {
            raw: command.to_string(),
            executable: None,
            args: vec![],
            redirections: vec![],
            assignments: vec![],
            is_subshell: false,
        });
    }

    ParsedCommand {
        segments,
        chain_operators: operators,
        parse_warnings: vec![ParseWarning::TreeSitterError("Used fallback parser".into())],
    }
}

/// Split command on unquoted operators, returning (segment_text, operator_after_it).
fn split_on_operators(command: &str) -> Vec<(String, Option<ChainOperator>)> {
    let mut results = vec![];
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
                current.push(ch);
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
                current.push(ch);
            }
            '|' if !in_single_quote && !in_double_quote => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                    results.push((current.clone(), Some(ChainOperator::Or)));
                    current.clear();
                } else {
                    results.push((current.clone(), Some(ChainOperator::Pipe)));
                    current.clear();
                }
            }
            '&' if !in_single_quote && !in_double_quote => {
                if chars.peek() == Some(&'&') {
                    chars.next();
                    results.push((current.clone(), Some(ChainOperator::And)));
                    current.clear();
                } else {
                    results.push((current.clone(), Some(ChainOperator::Background)));
                    current.clear();
                }
            }
            ';' if !in_single_quote && !in_double_quote => {
                results.push((current.clone(), Some(ChainOperator::Sequence)));
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        results.push((current, None));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_command_parsed_correctly() {
        let parsed = parse_fallback("ls -la /tmp");
        assert_eq!(parsed.segments.len(), 1);
        let seg = &parsed.segments[0];
        assert_eq!(seg.executable.as_deref(), Some("ls"));
        assert_eq!(seg.args.len(), 2);
        assert_eq!(seg.args[0].value, "-la");
        assert_eq!(seg.args[1].value, "/tmp");
    }

    #[test]
    fn pipeline_split_into_segments() {
        let parsed = parse_fallback("cat file.txt | grep pattern | wc -l");
        assert_eq!(parsed.segments.len(), 3);
        assert_eq!(parsed.segments[0].executable.as_deref(), Some("cat"));
        assert_eq!(parsed.segments[1].executable.as_deref(), Some("grep"));
        assert_eq!(parsed.segments[2].executable.as_deref(), Some("wc"));
        assert_eq!(parsed.chain_operators.len(), 2);
        assert_eq!(parsed.chain_operators[0], ChainOperator::Pipe);
        assert_eq!(parsed.chain_operators[1], ChainOperator::Pipe);
    }

    #[test]
    fn and_operator_split() {
        let parsed = parse_fallback("make && make install");
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.segments[0].executable.as_deref(), Some("make"));
        assert_eq!(parsed.segments[1].executable.as_deref(), Some("make"));
        assert_eq!(parsed.chain_operators.len(), 1);
        assert_eq!(parsed.chain_operators[0], ChainOperator::And);
    }

    #[test]
    fn or_operator_split() {
        let parsed = parse_fallback("test -f file || echo missing");
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.chain_operators[0], ChainOperator::Or);
    }

    #[test]
    fn sequence_operator_split() {
        let parsed = parse_fallback("cd /tmp ; ls");
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.chain_operators[0], ChainOperator::Sequence);
    }

    #[test]
    fn mixed_operators() {
        let parsed = parse_fallback("a | b && c || d ; e");
        assert_eq!(parsed.segments.len(), 5);
        assert_eq!(parsed.chain_operators[0], ChainOperator::Pipe);
        assert_eq!(parsed.chain_operators[1], ChainOperator::And);
        assert_eq!(parsed.chain_operators[2], ChainOperator::Or);
        assert_eq!(parsed.chain_operators[3], ChainOperator::Sequence);
    }

    #[test]
    fn quoted_pipe_not_split_single_quotes() {
        let parsed = parse_fallback("echo 'a | b'");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.chain_operators.len(), 0);
    }

    #[test]
    fn quoted_pipe_not_split_double_quotes() {
        let parsed = parse_fallback("echo \"a | b\"");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.chain_operators.len(), 0);
    }

    #[test]
    fn quoted_and_not_split() {
        let parsed = parse_fallback("echo 'a && b'");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.chain_operators.len(), 0);
    }

    #[test]
    fn empty_string_handled() {
        let parsed = parse_fallback("");
        assert_eq!(parsed.segments.len(), 1);
        assert!(parsed.segments[0].executable.is_none());
    }

    #[test]
    fn whitespace_only_handled() {
        let parsed = parse_fallback("   \t  ");
        assert_eq!(parsed.segments.len(), 1);
        assert!(parsed.segments[0].executable.is_none());
    }

    #[test]
    fn has_tree_sitter_error_warning() {
        let parsed = parse_fallback("echo hello");
        assert!(parsed
            .parse_warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::TreeSitterError(_))));
    }

    #[test]
    fn background_operator_detected() {
        let parsed = parse_fallback("sleep 10 &");
        // The segment before & should be present
        assert!(parsed.segments.len() >= 1);
        assert!(parsed.chain_operators.contains(&ChainOperator::Background));
    }

    #[test]
    fn expansion_detected_in_args() {
        let parsed = parse_fallback("echo $HOME");
        assert_eq!(parsed.segments.len(), 1);
        let arg = &parsed.segments[0].args[0];
        assert!(arg.has_expansion);
        assert_eq!(arg.expansion_type, Some(ExpansionType::Variable));
    }

    #[test]
    fn glob_expansion_detected() {
        let parsed = parse_fallback("ls *.txt");
        let arg = &parsed.segments[0].args[0];
        assert!(arg.has_expansion);
        assert_eq!(arg.expansion_type, Some(ExpansionType::Glob));
    }

    #[test]
    fn backtick_expansion_detected() {
        let parsed = parse_fallback("echo `whoami`");
        let arg = &parsed.segments[0].args[0];
        assert!(arg.has_expansion);
        assert_eq!(arg.expansion_type, Some(ExpansionType::Command));
    }

    #[test]
    fn subshell_detected() {
        let parsed = parse_fallback("(echo hello)");
        assert_eq!(parsed.segments.len(), 1);
        assert!(parsed.segments[0].is_subshell);
    }

    #[test]
    fn long_pipeline_segments() {
        let parsed = parse_fallback("a | b | c | d | e");
        assert_eq!(parsed.segments.len(), 5);
        assert_eq!(parsed.chain_operators.len(), 4);
        assert!(parsed
            .chain_operators
            .iter()
            .all(|op| *op == ChainOperator::Pipe));
    }

    #[test]
    fn executable_extraction_from_complex_command() {
        let parsed = parse_fallback("curl -X POST https://example.com -d @file.txt");
        let seg = &parsed.segments[0];
        assert_eq!(seg.executable.as_deref(), Some("curl"));
        assert!(seg.args.iter().any(|a| a.value == "-X"));
        assert!(seg.args.iter().any(|a| a.value == "POST"));
    }

    #[test]
    fn quoted_arg_detection_single() {
        let parsed = parse_fallback("echo 'hello world'");
        // The fallback splits on whitespace so quoted strings with spaces
        // get split -- but the first word 'hello starts with a quote
        let seg = &parsed.segments[0];
        assert!(seg.args.iter().any(|a| a.is_quoted));
    }

    #[test]
    fn quoted_arg_detection_double() {
        let parsed = parse_fallback("echo \"hello world\"");
        let seg = &parsed.segments[0];
        assert!(seg.args.iter().any(|a| a.is_quoted));
    }
}
