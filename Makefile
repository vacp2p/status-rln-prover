NATIVE_FLAGS = -C target-cpu=native

.PHONY: build
build:
	RUSTFLAGS="$(NATIVE_FLAGS)" cargo build --release

.PHONY: bench
bench:
	RUSTFLAGS="$(NATIVE_FLAGS)" cargo bench