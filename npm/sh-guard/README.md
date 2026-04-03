# sh-guard-cli

Semantic shell command safety classifier CLI distributed via npm.

This is a platform-specific binary wrapper. For full documentation, see the [main repository](https://github.com/aryanbhosale/sh-guard).

## Install

```bash
npm install -g sh-guard-cli
```

## Usage

```bash
sh-guard "rm -rf ~/"
# CRITICAL (100): File deletion: targeting home directory, recursive deletion

sh-guard "ls -la"
# SAFE (0): Information command
```
