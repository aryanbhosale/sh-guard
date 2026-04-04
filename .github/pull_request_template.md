## What

Brief description of the change.

## Why

Why is this change needed?

## How to test

```bash
cargo test --workspace
```

Or specific manual test steps:
```bash
sh-guard "example command"
```

## Checklist

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` has no errors
- [ ] `cargo fmt --all -- --check` passes
- [ ] Added tests for new functionality (if applicable)
