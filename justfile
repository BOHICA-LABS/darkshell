# DarkShell development commands
# Run `just --list` to see available recipes

set dotenv-load

# === CI Pipeline (matches GitHub Actions) ===

# Run the full CI pipeline locally
ci: check-fmt check-clippy build check-deny test test-doc

# === Check ===

# Check formatting (requires nightly)
check-fmt:
    cargo +nightly fmt --all -- --check

# Run clippy lints
check-clippy:
    cargo clippy --workspace --all-targets

# Check dependencies for advisories, licenses, bans
check-deny:
    cargo deny check advisories licenses bans

# Run all checks
check: check-fmt check-clippy check-deny

# === Build ===

# Build all workspace crates
build:
    cargo build --workspace

# Build release binary
build-release:
    cargo build --workspace --release

# === Test ===

# Run all tests
test:
    cargo test --workspace

# Run DarkShell-specific integration tests
test-darkshell:
    cargo test -p darkshell-mcp -p darkshell-observe -p darkshell-blueprint --all-targets
    cargo test -p openshell-cli --test 'darkshell_*'

# Run doc tests
test-doc:
    cargo test --workspace --doc

# === Coverage ===

# Generate coverage report (HTML)
coverage:
    cargo llvm-cov --workspace --html
    @echo "Report: target/llvm-cov/html/index.html"

# Generate coverage report (JSON for CI)
coverage-json:
    cargo llvm-cov --workspace --codecov --output-path codecov.json

# === Format ===

# Format all code
fmt:
    cargo +nightly fmt --all

# === Fork Validation ===

# Verify fork integrity (crate names, no unsafe, binary name)
fork-check:
    @echo "Checking crate names..."
    @grep '^name = "openshell-' crates/openshell-*/Cargo.toml > /dev/null && echo "✓ Crate names match upstream"
    @echo "Checking for unsafe in darkshell crates..."
    @! grep -r 'unsafe ' crates/darkshell-*/src/ --include='*.rs' -l && echo "✓ No unsafe code in darkshell crates"
    @echo "Checking binary name..."
    @cargo build -p openshell-cli 2>/dev/null && test -f target/debug/darkshell && echo "✓ Binary named darkshell"

# === Release ===

# Generate changelog
[group('release')]
changelog:
    git-cliff --config cliff.toml

# Show unreleased changes
[group('release')]
changelog-unreleased:
    git-cliff --config cliff.toml --unreleased

# Prepare a release: bump version, generate changelog, commit, tag
[group('release')]
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Preparing release {{ version }}..."
    # Update version in workspace Cargo.toml
    sed -i '' "s/^version = \".*\"/version = \"{{ version }}\"/" Cargo.toml
    cargo check
    # Generate full changelog
    git-cliff --config cliff.toml --tag "v{{ version }}" -o CHANGELOG.md
    git add Cargo.toml Cargo.lock CHANGELOG.md
    git commit -m "chore(release): prepare v{{ version }}"
    git tag -a "v{{ version }}" -m "Release v{{ version }}"
    echo ""
    echo "✓ Release v{{ version }} prepared."
    echo "  Push with: git push origin develop --tags"

# === Setup ===

# Install development tools
setup:
    rustup component add clippy
    rustup toolchain install nightly --component rustfmt
    cargo install cargo-deny cargo-llvm-cov cargo-audit git-cliff
    @echo "✓ All dev tools installed"
