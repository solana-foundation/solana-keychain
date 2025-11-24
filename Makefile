.PHONY: fmt build test

INTEGRATION_TESTS := test_privy_integration test_turnkey_integration test_vault_integration
SDKV2_ALL_FEATURES := all,sdk-v2,unsafe-debug,integration-tests
SDKV3_ALL_FEATURES := all,sdk-v3,unsafe-debug,integration-tests

fmt:
	@echo "Formatting code..."
	@cd rust && cargo fmt
	@echo "Running clippy with SDK v2..."
	@cd rust && cargo clippy --all-targets --no-default-features --features $(SDKV2_ALL_FEATURES) -- -D warnings
	@echo "Running clippy with SDK v3..."
	@cd rust && cargo clippy --all-targets --no-default-features --features $(SDKV3_ALL_FEATURES) -- -D warnings

test:
	@echo "Running tests with SDK v2..."
	@cd rust && cargo test --no-default-features --features all,sdk-v2,unsafe-debug
	@echo "Running tests with SDK v3..."
	@cd rust && cargo test --no-default-features --features all,sdk-v3,unsafe-debug

test-integration:
	@echo "Running integration tests with SDK v2..."
	@for test in $(INTEGRATION_TESTS); do \
		cd rust && cargo test --no-default-features --features all,sdk-v2,unsafe-debug,integration-tests tests::$$test:: || exit 1; \
	done
	@echo "Running integration tests with SDK v3..."
	@for test in $(INTEGRATION_TESTS); do \
		cd rust && cargo test --no-default-features --features all,sdk-v3,unsafe-debug,integration-tests tests::$$test:: || exit 1; \
	done

test-all: test test-integration

build:
	@echo "Building with SDK v2..."
	@cd rust && cargo build --features all,sdk-v2
	@echo "Building with SDK v3..."
	@cd rust && cargo build --no-default-features --features all,sdk-v3