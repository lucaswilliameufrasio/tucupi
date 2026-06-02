.PHONY: install binstall build test

install:
	cargo install --path .

binstall:
	cargo binstall tucupi

build:
	cargo build --release

test:
	cargo test
