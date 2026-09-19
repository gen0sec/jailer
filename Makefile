.PHONY: release release-dry help

# Releases are driven by cargo-release (configured in release.toml). The single
# source of truth for the version is [workspace.package].version in Cargo.toml;
# cargo-release bumps it, refreshes Cargo.lock, propagates it to install.sh and
# the README, commits, creates the annotated vX.Y.Z tag, and pushes.
#
# Pushing the tag triggers .github/workflows/release.yaml. That workflow builds
# in an old-glibc container, refuses to release a BPF object the kernel will not
# load, signs every artifact, and opens the GitHub release as a draft.
#
# BUMP may be a level keyword (patch|minor|major|alpha|beta|rc|release) or an
# explicit version (x.y.z). VERSION=x.y.z is accepted as an alias.

BUMP ?= patch
RELEASE_ARG := $(or $(VERSION),$(BUMP))

help:
	@echo "Available targets:"
	@echo "  release [BUMP=patch|minor|major|x.y.z]   - Cut a release: bump, commit, tag vX.Y.Z, push (triggers CI)"
	@echo "  release-dry [BUMP=...]                    - Preview the release without changing anything"
	@echo "  help                                      - Show this help message"
	@echo ""
	@echo "  (VERSION=x.y.z is accepted as an alias for BUMP)"
	@echo ""
	@echo "  Must be run from main. The release job needs GPG_PRIVATE_KEY and"
	@echo "  GPG_PASSPHRASE set as repository secrets, or it will refuse to"
	@echo "  publish unsigned artifacts."

release:
	@command -v cargo-release >/dev/null 2>&1 || { echo "ERROR: cargo-release not installed. Run: cargo install cargo-release" >&2; exit 1; }
	cargo release $(RELEASE_ARG) --execute --no-confirm

release-dry:
	@command -v cargo-release >/dev/null 2>&1 || { echo "ERROR: cargo-release not installed. Run: cargo install cargo-release" >&2; exit 1; }
	cargo release $(RELEASE_ARG)
