default:
  @just --list

all: spell format-check clippy-strict build-release

# Spelling
alias s := spell
alias sf := spell-fix

spell:
  typos --sort

spell-fix:
  typos -w

# Test
alias t := test

test:
  cargo test

# Formatting
alias f := format-fix
alias fc := format-check
alias format := format-fix

format-check:
  cargo fmt --check
  
format-fix:
  cargo fmt

# Linting
alias c := clippy-strict
alias ce := clippy-easy
alias clippy := clippy-strict

clippy-easy:
  cargo clippy --color always -- -D warnings

clippy-strict:
  cargo clippy --color always -- -W clippy::pedantic -D warnings

# Building
alias b := build-release
alias build := build-release

build-release:
  cargo build --release
