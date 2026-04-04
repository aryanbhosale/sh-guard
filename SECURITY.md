# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in sh-guard, please report it responsibly.

**Do not open a public issue.** Instead, use [GitHub's private vulnerability reporting](https://github.com/aryanbhosale/sh-guard/security/advisories/new) with:

- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Any suggested fix (optional)

You can expect an initial response within 72 hours. Once confirmed, a fix will be prioritized and released as soon as possible.

## Scope

sh-guard is a security tool that analyzes shell commands. Relevant security concerns include:

- False negatives: dangerous commands that sh-guard fails to detect
- Rule bypass: obfuscation techniques that evade detection
- Parser crashes: malformed input that causes panics or hangs
- Resource exhaustion: pathologically crafted commands that cause high memory/CPU usage
