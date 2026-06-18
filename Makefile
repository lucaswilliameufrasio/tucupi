.PHONY: install binstall build test setup format lint

install:
	cargo install --path .

binstall:
	cargo binstall tucupi

build:
	cargo build --release

test:
	cargo nextest run --all-targets

setup:
	cargo install cargo-nextest --locked
	cargo install cargo-binstall --locked

format:
	cargo fmt --all --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings
