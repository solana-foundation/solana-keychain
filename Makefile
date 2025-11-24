.PHONY: fmt build test test-integration test-all release

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

release:
	@echo "🚀 Release Process"
	@echo "=================="
	@echo ""
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "❌ Error: Working directory is not clean. Commit or stash changes first."; \
		exit 1; \
	fi
	@if ! command -v cargo-set-version >/dev/null 2>&1; then \
		echo "❌ Error: cargo-set-version not installed. Install with: cargo install cargo-edit"; \
		exit 1; \
	fi
	@if ! command -v git-cliff >/dev/null 2>&1; then \
		echo "❌ Error: git-cliff not installed. Install with: cargo install git-cliff"; \
		exit 1; \
	fi
	@echo "Current version: $$(cd rust && cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')"
	@read -p "Enter new version (e.g., 0.1.1): " VERSION; \
	if [ -z "$$VERSION" ]; then \
		echo "❌ Error: Version cannot be empty"; \
		exit 1; \
	fi; \
	echo ""; \
	echo "📝 Updating version to $$VERSION..."; \
	(cd rust && cargo set-version $$VERSION); \
	echo ""; \
	echo "📋 Generating CHANGELOG.md..."; \
	LAST_TAG=$$(git tag -l "v*" --sort=-version:refname | head -1); \
	if [ -z "$$LAST_TAG" ]; then \
		git-cliff $$(git rev-list --max-parents=0 HEAD)..HEAD --tag v$$VERSION --config .github/cliff.toml --output rust/CHANGELOG.md --strip all; \
	else \
		if [ -f rust/CHANGELOG.md ]; then \
			git-cliff $$LAST_TAG..HEAD --tag v$$VERSION --config .github/cliff.toml --strip all > rust/CHANGELOG.new.md; \
			cat rust/CHANGELOG.md >> rust/CHANGELOG.new.md; \
			mv rust/CHANGELOG.new.md rust/CHANGELOG.md; \
		else \
			git-cliff $$LAST_TAG..HEAD --tag v$$VERSION --config .github/cliff.toml --output rust/CHANGELOG.md --strip all; \
		fi; \
	fi; \
	echo ""; \
	echo "📦 Staging changes..."; \
	git add rust/Cargo.toml rust/CHANGELOG.md; \
	echo ""; \
	echo "✅ Release prepared!"; \
	echo ""; \
	echo "Next steps:"; \
	echo "  1. Review rust/CHANGELOG.md"; \
	echo "  2. Commit: git commit -m 'chore: release v$$VERSION'"; \
	echo "  3. Push to GitHub: git push"; \
	echo "  4. Trigger 'Publish Rust Crate' workflow on GitHub Actions (tags will be created automatically)"
