# Changelog

## 0.1.0 (2026-04-03)

Initial release.

### Features

- **AST parsing** via tree-sitter-bash with regex fallback
- **Semantic analysis** classifying intent, targets, flags, and risk factors
- **Pipeline taint analysis** tracking data flow through pipes to detect exfiltration
- **Risk scoring** (0-100) with four levels: safe, caution, danger, critical
- **MITRE ATT&CK mapping** for every detected risk
- **157 command rules** covering coreutils, git, curl, docker, kubectl, cloud CLIs
- **51 path rules** for secrets, system files, and config files
- **25 injection patterns** including command substitution, IFS injection, unicode tricks
- **15 zsh-specific rules** for module loading, glob qualifiers, equals expansion
- **61 GTFOBins entries** for binary capability detection
- **15 taint flow rules** for pipeline data-flow escalation
- **Custom rules** via TOML configuration
- **CLI** with colored output, JSON mode, stdin batch, and exit codes
- **MCP server** for Claude Code, Cursor, Cline, and Windsurf
- **`--setup` command** to auto-configure all AI coding agents
- **Node.js bindings** via napi-rs
- **Python bindings** via PyO3
- **Multi-platform binaries** for macOS (ARM/x64), Linux (x64/ARM64), Windows (x64)
