use crate::types::Shell;

// ========================================================
// Types
// ========================================================

#[derive(Debug, Clone)]
pub struct ParsedCommand {
    pub segments: Vec<CommandSegment>,
    pub chain_operators: Vec<ChainOperator>,
    pub parse_warnings: Vec<ParseWarning>,
}

#[derive(Debug, Clone)]
pub struct CommandSegment {
    pub raw: String,
    pub executable: Option<String>,
    pub args: Vec<Argument>,
    pub redirections: Vec<Redirection>,
    pub assignments: Vec<Assignment>,
    pub is_subshell: bool,
}

#[derive(Debug, Clone)]
pub struct Argument {
    pub value: String,
    pub is_quoted: bool,
    pub quote_type: Option<QuoteType>,
    pub has_expansion: bool,
    pub expansion_type: Option<ExpansionType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteType {
    Single,
    Double,
    AnsiC,
    Heredoc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpansionType {
    Variable,
    Command,
    Arithmetic,
    Process,
    Brace,
    Tilde,
    Glob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainOperator {
    Pipe,
    And,
    Or,
    Sequence,
    Background,
}

#[derive(Debug, Clone)]
pub struct Redirection {
    pub fd: Option<u32>,
    pub direction: RedirDirection,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirDirection {
    In,
    Out,
    Append,
    HereDoc,
    HereString,
}

#[derive(Debug, Clone)]
pub struct Assignment {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseWarning {
    ControlCharacters(Vec<u8>),
    UnicodeWhitespace(Vec<char>),
    UnbalancedQuotes,
    AnsiCQuoting,
    EscapedOperators,
    CarriageReturn,
    TreeSitterError(String),
}

// ========================================================
// Pre-processing: scan for suspicious patterns
// ========================================================

fn collect_warnings(command: &str) -> Vec<ParseWarning> {
    let mut warnings = Vec::new();

    // Control characters (0x00-0x08, 0x0E-0x1F, 0x7F) excluding \t(0x09), \n(0x0A), \r(0x0D)
    let control_chars: Vec<u8> = command
        .bytes()
        .filter(|&b| (b < 0x09) || (b > 0x0A && b < 0x0D) || (b > 0x0D && b < 0x20) || b == 0x7F)
        .collect();
    if !control_chars.is_empty() {
        warnings.push(ParseWarning::ControlCharacters(control_chars));
    }

    // Unicode whitespace (non-ASCII whitespace characters)
    let unicode_ws: Vec<char> = command
        .chars()
        .filter(|c| c.is_whitespace() && !c.is_ascii())
        .collect();
    if !unicode_ws.is_empty() {
        warnings.push(ParseWarning::UnicodeWhitespace(unicode_ws));
    }

    // Carriage return
    if command.contains('\r') {
        warnings.push(ParseWarning::CarriageReturn);
    }

    // ANSI-C quoting ($'...')
    if command.contains("$'") {
        warnings.push(ParseWarning::AnsiCQuoting);
    }

    // Escaped operators (\;, \|, \&)
    if command.contains("\\;") || command.contains("\\|") || command.contains("\\&") {
        warnings.push(ParseWarning::EscapedOperators);
    }

    warnings
}

// ========================================================
// Helpers for collecting child nodes via cursor
// ========================================================

/// Collect all direct children (named and anonymous) of a node.
fn all_children(node: tree_sitter::Node) -> Vec<tree_sitter::Node> {
    let mut cursor = node.walk();
    node.children(&mut cursor).collect()
}

/// Collect only named direct children of a node.
fn named_children(node: tree_sitter::Node) -> Vec<tree_sitter::Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

// ========================================================
// Public entry point
// ========================================================

pub fn parse(command: &str, _shell: Shell) -> ParsedCommand {
    let mut warnings = collect_warnings(command);

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("failed to set tree-sitter-bash language");

    let tree = match parser.parse(command, None) {
        Some(tree) => tree,
        None => {
            warnings.push(ParseWarning::TreeSitterError(
                "tree-sitter parse returned None".into(),
            ));
            return ParsedCommand {
                segments: vec![fallback_segment(command)],
                chain_operators: vec![],
                parse_warnings: warnings,
            };
        }
    };

    let root = tree.root_node();

    if root.has_error() {
        warnings.push(ParseWarning::TreeSitterError(
            "parse tree contains error nodes".into(),
        ));
    }

    let mut segments = Vec::new();
    let mut operators = Vec::new();

    walk_program(root, command.as_bytes(), &mut segments, &mut operators);

    // If we got nothing out of the walk, produce a single empty segment
    if segments.is_empty() {
        segments.push(empty_segment());
    }

    ParsedCommand {
        segments,
        chain_operators: operators,
        parse_warnings: warnings,
    }
}

// ========================================================
// CST walking
// ========================================================

fn walk_program(
    node: tree_sitter::Node,
    src: &[u8],
    segments: &mut Vec<CommandSegment>,
    operators: &mut Vec<ChainOperator>,
) {
    let kind = node.kind();
    match kind {
        "program" => {
            let children = named_children(node);
            let child_count = children.len();
            for (idx, child) in children.iter().enumerate() {
                if idx > 0 && child_count > 1 {
                    let prev_len = segments.len();
                    walk_program(*child, src, segments, operators);
                    if segments.len() > prev_len && prev_len > 0 {
                        operators.push(ChainOperator::Sequence);
                    }
                } else {
                    walk_program(*child, src, segments, operators);
                }
            }
        }
        "list" => {
            walk_list(node, src, segments, operators);
        }
        "pipeline" => {
            walk_pipeline(node, src, segments, operators);
        }
        "command" => {
            segments.push(extract_command(node, src));
        }
        "redirected_statement" => {
            segments.push(extract_redirected_statement(node, src));
        }
        "subshell" => {
            let mut seg = empty_segment();
            seg.is_subshell = true;
            seg.raw = node_text(node, src).to_string();
            for child in named_children(node) {
                match child.kind() {
                    "command" | "pipeline" | "list" | "redirected_statement" => {
                        let inner = extract_any_command(child, src);
                        if seg.executable.is_none() {
                            seg.executable = inner.executable;
                        }
                        seg.args.extend(inner.args);
                        seg.redirections.extend(inner.redirections);
                        seg.assignments.extend(inner.assignments);
                    }
                    _ => {}
                }
            }
            segments.push(seg);
        }
        "variable_assignment" => {
            let mut seg = empty_segment();
            seg.raw = node_text(node, src).to_string();
            if let Some(assignment) = extract_assignment(node, src) {
                seg.assignments.push(assignment);
            }
            segments.push(seg);
        }
        "negated_command"
        | "compound_statement"
        | "if_statement"
        | "while_statement"
        | "for_statement"
        | "case_statement"
        | "function_definition" => {
            let mut seg = empty_segment();
            seg.raw = node_text(node, src).to_string();
            segments.push(seg);
        }
        _ => {
            for child in named_children(node) {
                walk_program(child, src, segments, operators);
            }
        }
    }
}

fn walk_list(
    node: tree_sitter::Node,
    src: &[u8],
    segments: &mut Vec<CommandSegment>,
    operators: &mut Vec<ChainOperator>,
) {
    for child in all_children(node) {
        match child.kind() {
            "&&" => operators.push(ChainOperator::And),
            "||" => operators.push(ChainOperator::Or),
            ";" => operators.push(ChainOperator::Sequence),
            "&" => operators.push(ChainOperator::Background),
            _ => {
                walk_program(child, src, segments, operators);
            }
        }
    }
}

fn walk_pipeline(
    node: tree_sitter::Node,
    src: &[u8],
    segments: &mut Vec<CommandSegment>,
    operators: &mut Vec<ChainOperator>,
) {
    for child in all_children(node) {
        match child.kind() {
            "|" | "|&" => {
                operators.push(ChainOperator::Pipe);
            }
            _ if child.is_named() => {
                walk_program(child, src, segments, operators);
            }
            _ => {}
        }
    }
}

// ========================================================
// Command extraction
// ========================================================

fn extract_command(node: tree_sitter::Node, src: &[u8]) -> CommandSegment {
    let mut seg = empty_segment();
    seg.raw = node_text(node, src).to_string();

    for child in all_children(node) {
        let kind = child.kind();
        match kind {
            "command_name" => {
                seg.executable = Some(node_text(child, src).to_string());
            }
            "variable_assignment" => {
                if let Some(assignment) = extract_assignment(child, src) {
                    seg.assignments.push(assignment);
                }
            }
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                if let Some(redir) = extract_redirection(child, src) {
                    seg.redirections.push(redir);
                }
            }
            _ if child.is_named() && kind != "command_name" => {
                let arg = extract_argument(child, src);
                seg.args.push(arg);
            }
            _ => {}
        }
    }

    seg
}

fn extract_redirected_statement(node: tree_sitter::Node, src: &[u8]) -> CommandSegment {
    let mut seg = empty_segment();
    seg.raw = node_text(node, src).to_string();

    for child in all_children(node) {
        match child.kind() {
            "command" => {
                let inner = extract_command(child, src);
                seg.executable = inner.executable;
                seg.args = inner.args;
                seg.assignments = inner.assignments;
                seg.redirections.extend(inner.redirections);
            }
            "pipeline" => {
                seg.raw = node_text(child, src).to_string();
            }
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                if let Some(redir) = extract_redirection(child, src) {
                    seg.redirections.push(redir);
                }
            }
            _ => {}
        }
    }

    seg
}

fn extract_any_command(node: tree_sitter::Node, src: &[u8]) -> CommandSegment {
    match node.kind() {
        "command" => extract_command(node, src),
        "redirected_statement" => extract_redirected_statement(node, src),
        "pipeline" => {
            let mut seg = empty_segment();
            seg.raw = node_text(node, src).to_string();
            for child in named_children(node) {
                if child.kind() == "command" {
                    return extract_command(child, src);
                }
            }
            seg
        }
        "list" => {
            let mut seg = empty_segment();
            seg.raw = node_text(node, src).to_string();
            for child in named_children(node) {
                if matches!(
                    child.kind(),
                    "command" | "pipeline" | "redirected_statement"
                ) {
                    return extract_any_command(child, src);
                }
            }
            seg
        }
        _ => {
            let mut seg = empty_segment();
            seg.raw = node_text(node, src).to_string();
            seg
        }
    }
}

// ========================================================
// Argument extraction with expansion/quote detection
// ========================================================

fn extract_argument(node: tree_sitter::Node, src: &[u8]) -> Argument {
    let text = node_text(node, src).to_string();
    let kind = node.kind();

    let (is_quoted, quote_type) = match kind {
        "string" | "translated_string" => (true, Some(QuoteType::Double)),
        "raw_string" => (true, Some(QuoteType::Single)),
        "ansi_c_string" => (true, Some(QuoteType::AnsiC)),
        "heredoc_body" => (true, Some(QuoteType::Heredoc)),
        "concatenation" => {
            let mut found_quote = false;
            let mut qt = None;
            for child in named_children(node) {
                match child.kind() {
                    "string" | "translated_string" => {
                        found_quote = true;
                        qt = Some(QuoteType::Double);
                    }
                    "raw_string" => {
                        found_quote = true;
                        qt = Some(QuoteType::Single);
                    }
                    "ansi_c_string" => {
                        found_quote = true;
                        qt = Some(QuoteType::AnsiC);
                    }
                    _ => {}
                }
            }
            (found_quote, qt)
        }
        _ => (false, None),
    };

    let (has_expansion, expansion_type) = detect_expansion(node, src, &text);

    Argument {
        value: text,
        is_quoted,
        quote_type,
        has_expansion,
        expansion_type,
    }
}

fn detect_expansion(
    node: tree_sitter::Node,
    src: &[u8],
    text: &str,
) -> (bool, Option<ExpansionType>) {
    // First check child nodes for tree-sitter recognized expansions
    if let Some(exp) = detect_expansion_from_children(node, src) {
        return (true, Some(exp));
    }

    // Fallback: text pattern matching
    detect_expansion_from_text(text)
}

fn detect_expansion_from_children(node: tree_sitter::Node, src: &[u8]) -> Option<ExpansionType> {
    // Check the node itself
    match node.kind() {
        "simple_expansion" | "expansion" => return Some(ExpansionType::Variable),
        "command_substitution" => return Some(ExpansionType::Command),
        "arithmetic_expansion" => return Some(ExpansionType::Arithmetic),
        "process_substitution" => return Some(ExpansionType::Process),
        _ => {}
    }

    // Walk children recursively
    for child in named_children(node) {
        if let Some(exp) = detect_expansion_from_children(child, src) {
            return Some(exp);
        }
    }

    None
}

fn detect_expansion_from_text(text: &str) -> (bool, Option<ExpansionType>) {
    // Check for backtick command substitution
    if text.contains('`') {
        return (true, Some(ExpansionType::Command));
    }

    // Check for $(...) or ${...} or $VAR
    if text.contains("$((") {
        return (true, Some(ExpansionType::Arithmetic));
    }
    if text.contains("$(") {
        return (true, Some(ExpansionType::Command));
    }
    if text.contains("${") || (text.contains('$') && text.len() > 1) {
        return (true, Some(ExpansionType::Variable));
    }

    // Tilde expansion
    if text.starts_with('~') {
        return (true, Some(ExpansionType::Tilde));
    }

    // Glob patterns
    if text.contains('*') || text.contains('?') || text.contains('[') {
        return (true, Some(ExpansionType::Glob));
    }

    // Brace expansion
    if text.contains('{') && text.contains('}') && text.contains(',') {
        return (true, Some(ExpansionType::Brace));
    }

    (false, None)
}

// ========================================================
// Redirection extraction
// ========================================================

fn extract_redirection(node: tree_sitter::Node, src: &[u8]) -> Option<Redirection> {
    match node.kind() {
        "file_redirect" => {
            let mut fd = None;
            let mut direction = RedirDirection::Out;
            let mut target = String::new();

            for child in all_children(node) {
                let child_text = node_text(child, src);
                match child.kind() {
                    "file_descriptor" => {
                        fd = child_text.parse::<u32>().ok();
                    }
                    ">" => {
                        direction = RedirDirection::Out;
                    }
                    "<" => {
                        direction = RedirDirection::In;
                    }
                    ">>" => {
                        direction = RedirDirection::Append;
                    }
                    "&>" | "&>>" | ">&" => {
                        direction = RedirDirection::Out;
                    }
                    "<&" => {
                        direction = RedirDirection::In;
                    }
                    "word" | "number" | "string" | "raw_string" | "concatenation" => {
                        target = child_text.to_string();
                    }
                    _ if child.is_named() => {
                        target = child_text.to_string();
                    }
                    _ => {}
                }
            }

            Some(Redirection {
                fd,
                direction,
                target,
            })
        }
        "heredoc_redirect" => Some(Redirection {
            fd: None,
            direction: RedirDirection::HereDoc,
            target: node_text(node, src).to_string(),
        }),
        "herestring_redirect" => Some(Redirection {
            fd: None,
            direction: RedirDirection::HereString,
            target: node_text(node, src).to_string(),
        }),
        _ => None,
    }
}

// ========================================================
// Variable assignment extraction
// ========================================================

fn extract_assignment(node: tree_sitter::Node, src: &[u8]) -> Option<Assignment> {
    if node.kind() != "variable_assignment" {
        return None;
    }

    let mut name = String::new();
    let mut value = String::new();

    for child in named_children(node) {
        match child.kind() {
            "variable_name" => {
                name = node_text(child, src).to_string();
            }
            _ => {
                value = node_text(child, src).to_string();
            }
        }
    }

    // If we didn't find a variable_name child, try parsing from text
    if name.is_empty() {
        let text = node_text(node, src);
        if let Some(eq_pos) = text.find('=') {
            name = text[..eq_pos].to_string();
            value = text[eq_pos + 1..].to_string();
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(Assignment { name, value })
}

// ========================================================
// Helpers
// ========================================================

fn node_text<'a>(node: tree_sitter::Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn empty_segment() -> CommandSegment {
    CommandSegment {
        raw: String::new(),
        executable: None,
        args: vec![],
        redirections: vec![],
        assignments: vec![],
        is_subshell: false,
    }
}

fn fallback_segment(command: &str) -> CommandSegment {
    CommandSegment {
        raw: command.to_string(),
        executable: None,
        args: vec![],
        redirections: vec![],
        assignments: vec![],
        is_subshell: false,
    }
}
